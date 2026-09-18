#!/usr/bin/env python3
"""
main.py — BugBounty-Recon Daily Reconnaissance Pipeline
=========================================================
Developer : Ahmed Wael
Purpose   : Orchestrate a full daily recon cycle for a designated set of target
            part files:
              1. Load targets from the pre-split part files.
              2. Discover subdomains with subfinder (fast/all-sources).
              3. Probe discovered subdomains with httpx (active host detection).
              4. Diff against the persistent baseline to isolate new assets.
              5. Triage new active hosts against high-value keyword list.
              6. Generate a professional branded HTML email report.
              7. Dispatch the report via SMTP.
              8. Update the persistent baseline file.
License   : MIT
"""

import json
import logging
import os
import smtplib
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from html import escape
from pathlib import Path

import requests  # used only for the graceful-fallback split if parts are missing

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
PARTS_DIR     = Path("parts")
BASELINE_FILE = Path("baseline_subs.txt")
TOTAL_PARTS   = 21

# Subprocess timeouts (seconds)
SUBFINDER_TIMEOUT = 3600   # 1 hour per batch
HTTPX_TIMEOUT_CLI = 3600   # 1 hour for the full probe phase

# httpx per-host settings (passed as CLI flags)
HTTPX_THREADS      = 50
HTTPX_HOST_TIMEOUT = 10    # seconds per host
HTTPX_RATE_LIMIT   = 150   # requests/second

# High-value keyword list — any subdomain matching one of these gets flagged
HIGH_VALUE_KEYWORDS: list[str] = [
    "admin", "administrator", "manage", "management", "manager",
    "dev", "develop", "development", "developer",
    "staging", "stage", "stg",
    "test", "testing", "qa", "uat",
    "api", "graphql", "rest", "swagger", "openapi",
    "login", "signin", "auth", "sso", "oauth", "ldap", "saml",
    "backup", "backups", "bak",
    "portal", "dashboard", "console", "panel",
    "internal", "intranet", "corp", "corporate", "private",
    "vpn", "remote", "access", "gateway",
    "jenkins", "gitlab", "jira", "confluence", "bitbucket", "sonar",
    "grafana", "kibana", "prometheus", "elastic", "logstash", "datadog",
    "phpmyadmin", "adminer", "cpanel", "whm", "plesk", "webmin",
    "monitor", "metrics", "status", "health", "nagios", "zabbix",
    "beta", "canary", "preview", "sandbox",
    "mail", "smtp", "imap", "webmail", "exchange",
    "ftp", "sftp",
    "db", "database", "sql", "mysql", "postgres", "mongo", "redis",
    "cache", "memcache",
    "old", "legacy", "archive",
    "infra", "infrastructure", "deploy", "deployment", "cd", "ci",
]


# ---------------------------------------------------------------------------
# Step 1 — Load targets from part files
# ---------------------------------------------------------------------------
def load_part_targets(part_numbers: list[int]) -> list[str]:
    """
    Read targets from the pre-split part files for the given part numbers.
    Returns a deduplicated, flat list of all targets across those parts.

    Developer: Ahmed Wael
    """
    all_targets: list[str] = []
    seen: set[str] = set()

    for num in part_numbers:
        part_file = PARTS_DIR / f"part_{num:02d}.txt"
        if not part_file.exists():
            log.warning("Part file not found: %s  — skipping.", part_file)
            continue

        lines = [
            l.strip().lower()
            for l in part_file.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.strip().startswith("#")
        ]
        before = len(all_targets)
        for line in lines:
            if line not in seen:
                seen.add(line)
                all_targets.append(line)

        added = len(all_targets) - before
        log.info("Part %02d loaded: %d targets  (%s)", num, added, part_file)

    log.info("Total targets loaded from parts %s: %d", part_numbers, len(all_targets))
    return all_targets


# ---------------------------------------------------------------------------
# Step 2 — Run subfinder
# ---------------------------------------------------------------------------
def run_subfinder(targets: list[str]) -> set[str]:
    """
    Write *targets* to a temp file and invoke subfinder (silent/all-sources).
    Returns the full set of discovered subdomains (lower-cased).

    Developer: Ahmed Wael
    """
    if not targets:
        log.warning("No targets provided to subfinder. Skipping.")
        return set()

    discovered: set[str] = set()

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="sf_targets_"
    ) as tf:
        tf.write("\n".join(targets))
        targets_path = tf.name

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="sf_output_"
    ) as of:
        output_path = of.name

    log.info("Running subfinder on %d targets …", len(targets))

    try:
        result = subprocess.run(
            [
                "subfinder",
                "-dL",     targets_path,
                "-o",      output_path,
                "-silent",
                "-all",
            ],
            capture_output=True,
            text=True,
            timeout=SUBFINDER_TIMEOUT,
        )

        if result.returncode != 0:
            log.warning(
                "subfinder exited with code %d. stderr: %s",
                result.returncode,
                result.stderr[:500],
            )

        raw = Path(output_path).read_text(encoding="utf-8", errors="ignore")
        discovered = {
            ln.strip().lower()
            for ln in raw.splitlines()
            if ln.strip()
        }
        log.info("subfinder discovered %d subdomains.", len(discovered))

    except FileNotFoundError:
        log.error("subfinder binary not found. Ensure it is installed and on PATH.")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        log.error("subfinder timed out after %d seconds.", SUBFINDER_TIMEOUT)
        sys.exit(1)
    finally:
        Path(targets_path).unlink(missing_ok=True)
        Path(output_path).unlink(missing_ok=True)

    return discovered


# ---------------------------------------------------------------------------
# Step 3 — Run httpx
# ---------------------------------------------------------------------------
def run_httpx(subdomains: set[str]) -> list[dict]:
    """
    Probe *subdomains* with httpx to identify active HTTP/HTTPS hosts.
    Returns a list of result dicts (one per active host).

    Gracefully degrades if httpx is not installed — returns empty list.

    Developer: Ahmed Wael
    """
    if not subdomains:
        log.info("No subdomains to probe with httpx.")
        return []

    results: list[dict] = []

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="hx_input_"
    ) as tf:
        tf.write("\n".join(sorted(subdomains)))
        input_path = tf.name

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, prefix="hx_output_"
    ) as of:
        output_path = of.name

    log.info("Running httpx on %d subdomains (threads=%d) …", len(subdomains), HTTPX_THREADS)

    try:
        proc = subprocess.run(
            [
                "httpx",
                "-l",              input_path,
                "-o",              output_path,
                "-json",
                "-silent",
                "-sc",                              # include status code
                "-title",                           # include page title
                "-follow-redirects",
                "-prefer-https",
                "-threads",        str(HTTPX_THREADS),
                "-timeout",        str(HTTPX_HOST_TIMEOUT),
                "-rate-limit",     str(HTTPX_RATE_LIMIT),
                "-retries",        "1",
            ],
            capture_output=True,
            text=True,
            timeout=HTTPX_TIMEOUT_CLI,
        )

        if proc.returncode != 0:
            log.warning(
                "httpx exited with code %d. stderr: %s",
                proc.returncode,
                proc.stderr[:500],
            )

        raw_lines = Path(output_path).read_text(encoding="utf-8", errors="ignore").splitlines()
        for line in raw_lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                results.append(obj)
            except json.JSONDecodeError:
                continue  # skip malformed lines

        log.info("httpx probed %d active hosts.", len(results))

    except FileNotFoundError:
        log.warning(
            "httpx binary not found. HTTP probing phase skipped. "
            "Install httpx: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
        )
    except subprocess.TimeoutExpired:
        log.error("httpx timed out after %d seconds.", HTTPX_TIMEOUT_CLI)
    finally:
        Path(input_path).unlink(missing_ok=True)
        Path(output_path).unlink(missing_ok=True)

    return results


# ---------------------------------------------------------------------------
# Step 4 — Parse httpx results
# ---------------------------------------------------------------------------
def parse_httpx_results(raw_results: list[dict]) -> list[dict]:
    """
    Normalise each httpx JSON result into a clean, consistent dict.

    Returned keys per host:
        host        — original input domain
        url         — final resolved URL
        status_code — integer HTTP status code
        title       — page title string (empty string if absent)
        server      — webserver header value (empty string if absent)

    Developer: Ahmed Wael
    """
    parsed: list[dict] = []
    for item in raw_results:
        host = (item.get("input") or item.get("host") or "").strip().lower()
        # Strip scheme if the input field contains a URL
        if "://" in host:
            host = host.split("://", 1)[1].rstrip("/")
        if not host:
            continue

        parsed.append(
            {
                "host":        host,
                "url":         item.get("url", ""),
                "status_code": item.get("status-code", 0),
                "title":       (item.get("title") or "").strip(),
                "server":      (item.get("webserver") or "").strip(),
            }
        )
    return parsed


# ---------------------------------------------------------------------------
# Step 5 — Baseline management
# ---------------------------------------------------------------------------
def load_baseline(path: Path) -> set[str]:
    """Read the persistent baseline into a set; return empty set if absent."""
    if not path.exists():
        log.info("No baseline file found at '%s'. Starting fresh.", path)
        return set()
    entries = {
        ln.strip().lower()
        for ln in path.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    }
    log.info("Baseline loaded: %d known subdomains.", len(entries))
    return entries


def update_baseline(
    path: Path, new_subs: set[str], baseline_subs: set[str]
) -> None:
    """Merge *new_subs* into *baseline_subs* and write the result back to disk."""
    merged = baseline_subs | new_subs
    path.write_text(
        "# BugBounty-Recon baseline — auto-managed by main.py  |  Developer: Ahmed Wael\n"
        + "\n".join(sorted(merged))
        + "\n",
        encoding="utf-8",
    )
    log.info(
        "Baseline updated: %d total entries (+%d new).", len(merged), len(new_subs)
    )


# ---------------------------------------------------------------------------
# Step 6 — Diff
# ---------------------------------------------------------------------------
def diff_subdomains(current: set[str], baseline: set[str]) -> set[str]:
    """Return subdomains present in *current* but absent from *baseline*."""
    new_subs = current - baseline
    log.info(
        "Diff: %d current | %d baseline | %d NEW",
        len(current),
        len(baseline),
        len(new_subs),
    )
    return new_subs


# ---------------------------------------------------------------------------
# Step 7 — Triage high-value targets
# ---------------------------------------------------------------------------
def triage_high_value(probed_hosts: list[dict]) -> list[dict]:
    """
    Filter *probed_hosts* for entries whose hostname contains at least one
    HIGH_VALUE_KEYWORDS token (case-insensitive substring match).

    Developer: Ahmed Wael
    """
    flagged: list[dict] = []
    for host_info in probed_hosts:
        host_lower = host_info["host"].lower()
        matched_keywords = [kw for kw in HIGH_VALUE_KEYWORDS if kw in host_lower]
        if matched_keywords:
            flagged.append({**host_info, "keywords": matched_keywords})
    log.info(
        "High-value triage: %d / %d active hosts flagged.",
        len(flagged),
        len(probed_hosts),
    )
    return flagged


# ---------------------------------------------------------------------------
# Step 8 — HTML report generation
# ---------------------------------------------------------------------------
def _status_badge(code: int) -> str:
    """Return an inline-styled HTML badge coloured by HTTP status family."""
    if code == 0:
        colour, bg = "#718096", "#EDF2F7"
    elif 200 <= code < 300:
        colour, bg = "#276749", "#C6F6D5"
    elif 300 <= code < 400:
        colour, bg = "#744210", "#FEFCBF"
    elif 400 <= code < 500:
        colour, bg = "#742A2A", "#FED7D7"
    else:
        colour, bg = "#553C9A", "#E9D8FD"

    label = str(code) if code else "N/A"
    return (
        f'<span style="display:inline-block;padding:2px 8px;border-radius:12px;'
        f'font-size:12px;font-weight:700;color:{colour};background:{bg};">'
        f"{label}</span>"
    )


def _keyword_tags(keywords: list[str]) -> str:
    """Render a list of keyword strings as small coloured HTML tags."""
    parts = []
    for kw in keywords[:5]:  # cap at 5 tags per row
        parts.append(
            f'<span style="display:inline-block;margin:1px 2px;padding:1px 6px;'
            f'border-radius:10px;font-size:11px;font-weight:600;'
            f'color:#c05621;background:#FEEBCB;">{escape(kw)}</span>'
        )
    return " ".join(parts)


def generate_html_report(
    new_subs: set[str],
    active_hosts: list[dict],
    high_value_targets: list[dict],
    parts_processed: list[int],
    run_timestamp: str,
) -> str:
    """
    Build a fully self-contained, responsive HTML email report.

    Developer: Ahmed Wael
    Report generated by: BugBounty-Recon  |  Developed by Ahmed Wael
    """
    total_new    = len(new_subs)
    total_active = len(active_hosts)
    total_hv     = len(high_value_targets)
    parts_label  = ", ".join(f"Part {p:02d}" for p in parts_processed)

    # ── Stats cards ────────────────────────────────────────────────────────
    def stat_card(value: str, label: str, bg: str, icon: str) -> str:
        return f"""
        <td width="33%" align="center" style="padding:8px;">
          <div style="background:{bg};border-radius:12px;padding:20px 10px;">
            <div style="font-size:28px;">{icon}</div>
            <div style="font-size:32px;font-weight:800;color:#1a202c;margin:4px 0;">{value}</div>
            <div style="font-size:12px;color:#718096;font-weight:600;text-transform:uppercase;
                        letter-spacing:0.5px;">{label}</div>
          </div>
        </td>"""

    # ── Active-hosts table rows ────────────────────────────────────────────
    table_rows = ""
    if active_hosts:
        for h in sorted(active_hosts, key=lambda x: x.get("status_code", 0)):
            row_bg    = "#fffbeb" if any(h["host"] == hv["host"] for hv in high_value_targets) else "#ffffff"
            badge     = _status_badge(h.get("status_code", 0))
            hv_match  = next((hv for hv in high_value_targets if hv["host"] == h["host"]), None)
            tags_html = _keyword_tags(hv_match["keywords"]) if hv_match else ""
            flag_icon = "🚨 " if hv_match else ""

            table_rows += f"""
            <tr style="background:{row_bg};border-bottom:1px solid #e2e8f0;">
              <td style="padding:10px 12px;font-size:13px;color:#2d3748;word-break:break-all;">
                {flag_icon}<a href="https://{escape(h['host'])}" style="color:#2b6cb0;text-decoration:none;">
                {escape(h['host'])}</a>
              </td>
              <td style="padding:10px 12px;text-align:center;">{badge}</td>
              <td style="padding:10px 12px;font-size:12px;color:#4a5568;max-width:200px;
                         overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                {escape(h.get("title", "") or "—")}
              </td>
              <td style="padding:10px 12px;">{tags_html}</td>
            </tr>"""
    else:
        table_rows = """
            <tr>
              <td colspan="4" style="padding:24px;text-align:center;color:#a0aec0;font-style:italic;">
                No active HTTP hosts detected in this batch.
              </td>
            </tr>"""

    # ── DNS-only new subs (not in active_hosts) ────────────────────────────
    active_host_names = {h["host"] for h in active_hosts}
    dns_only = sorted(new_subs - active_host_names)
    dns_rows = ""
    if dns_only:
        dns_rows = "".join(
            f'<tr style="border-bottom:1px solid #edf2f7;">'
            f'<td style="padding:6px 12px;font-size:12px;color:#4a5568;">{escape(d)}</td>'
            f"</tr>"
            for d in dns_only[:200]  # cap at 200 for email size
        )
        if len(dns_only) > 200:
            dns_rows += (
                f'<tr><td style="padding:6px 12px;font-size:12px;color:#a0aec0;'
                f'font-style:italic;">… and {len(dns_only)-200} more (see baseline_subs.txt)</td></tr>'
            )

    # ── High-value section ─────────────────────────────────────────────────
    hv_rows = ""
    if high_value_targets:
        for hv in sorted(high_value_targets, key=lambda x: x.get("status_code", 0)):
            badge    = _status_badge(hv.get("status_code", 0))
            tag_html = _keyword_tags(hv.get("keywords", []))
            hv_rows += f"""
              <tr style="border-bottom:1px solid #feebc8;">
                <td style="padding:10px 12px;font-size:13px;color:#2d3748;word-break:break-all;">
                  <a href="https://{escape(hv['host'])}" style="color:#c05621;font-weight:600;
                     text-decoration:none;">🎯 {escape(hv['host'])}</a>
                </td>
                <td style="padding:10px 12px;text-align:center;">{badge}</td>
                <td style="padding:10px 12px;font-size:12px;color:#4a5568;">
                  {escape(hv.get("title", "") or "—")}
                </td>
                <td style="padding:10px 12px;">{tag_html}</td>
              </tr>"""
    else:
        hv_rows = (
            '<tr><td colspan="4" style="padding:20px;text-align:center;'
            'color:#a0aec0;font-style:italic;">No high-value targets flagged in this batch.</td></tr>'
        )

    # ── Full HTML document ─────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1.0" />
  <title>BugBounty-Recon Report — Ahmed Wael</title>
</head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:Arial,Helvetica,sans-serif;">

<!-- ═══════════════════════════════════════════ HEADER ══ -->
<table width="100%" cellpadding="0" cellspacing="0"
       style="background:linear-gradient(135deg,#1a1a2e 0%,#16213e 60%,#0f3460 100%);">
  <tr>
    <td align="center" style="padding:36px 24px 28px;">
      <table cellpadding="0" cellspacing="0" style="max-width:680px;">
        <tr>
          <td align="center">
            <div style="display:inline-block;background:#e94560;border-radius:50%;
                        width:54px;height:54px;line-height:54px;text-align:center;
                        font-size:26px;margin-bottom:12px;">🔍</div>
            <h1 style="margin:0;font-size:28px;font-weight:900;color:#ffffff;
                        letter-spacing:-0.5px;">BugBounty-Recon</h1>
            <p style="margin:6px 0 0;font-size:15px;color:#a0aec0;">
              Daily Reconnaissance Intelligence Report
            </p>
            <p style="margin:6px 0 0;font-size:12px;color:#718096;">
              Developed by <strong style="color:#e94560;">Ahmed Wael</strong>
              &nbsp;·&nbsp; {escape(run_timestamp)}
            </p>
            <p style="margin:8px 0 0;font-size:12px;color:#4a5568;
                       background:rgba(255,255,255,0.06);border-radius:20px;
                       padding:4px 16px;display:inline-block;">
              Processing: {escape(parts_label)}
            </p>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>

<!-- ═══════════════════════════════════════════ STATS CARDS ══ -->
<table width="100%" cellpadding="0" cellspacing="0" style="max-width:680px;margin:24px auto 0;">
  <tr>
    {stat_card(str(total_new),    "New Subdomains",      "#ebf8ff", "🌐")}
    {stat_card(str(total_active), "Active HTTP Hosts",   "#f0fff4", "✅")}
    {stat_card(str(total_hv),     "High-Value Alerts",   "#fffaf0", "🚨")}
  </tr>
</table>

<!-- ═══════════════════════════════════════════ ACTIVE HOSTS TABLE ══ -->
<table width="100%" cellpadding="0" cellspacing="0"
       style="max-width:680px;margin:24px auto 0;background:#ffffff;
              border-radius:16px;overflow:hidden;
              box-shadow:0 2px 16px rgba(0,0,0,0.07);">
  <tr>
    <td style="background:#1a1a2e;padding:16px 20px;">
      <h2 style="margin:0;font-size:16px;font-weight:700;color:#ffffff;">
        ✅ New Active HTTP Hosts
      </h2>
      <p style="margin:4px 0 0;font-size:12px;color:#718096;">
        Subdomains responding over HTTP/S in this batch run
      </p>
    </td>
  </tr>
  <tr>
    <td style="padding:0;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <thead>
          <tr style="background:#f7fafc;border-bottom:2px solid #e2e8f0;">
            <th style="padding:10px 12px;text-align:left;font-size:12px;
                       color:#718096;font-weight:700;text-transform:uppercase;">Hostname</th>
            <th style="padding:10px 12px;text-align:center;font-size:12px;
                       color:#718096;font-weight:700;text-transform:uppercase;width:80px;">Status</th>
            <th style="padding:10px 12px;text-align:left;font-size:12px;
                       color:#718096;font-weight:700;text-transform:uppercase;width:200px;">Title</th>
            <th style="padding:10px 12px;text-align:left;font-size:12px;
                       color:#718096;font-weight:700;text-transform:uppercase;">Tags</th>
          </tr>
        </thead>
        <tbody>
          {table_rows}
        </tbody>
      </table>
    </td>
  </tr>
</table>

<!-- ═══════════════════════════════════════════ HIGH-VALUE TARGETS ══ -->
<table width="100%" cellpadding="0" cellspacing="0"
       style="max-width:680px;margin:24px auto 0;background:#fff8f0;
              border-radius:16px;overflow:hidden;border:2px solid #fbd38d;
              box-shadow:0 2px 16px rgba(0,0,0,0.05);">
  <tr>
    <td style="background:linear-gradient(90deg,#c05621,#dd6b20);padding:16px 20px;">
      <h2 style="margin:0;font-size:16px;font-weight:700;color:#ffffff;">
        🚨 High-Value Targets — Manual Inspection Required
      </h2>
      <p style="margin:4px 0 0;font-size:12px;color:#fef3c7;">
        Hosts matching sensitive keywords — review immediately
      </p>
    </td>
  </tr>
  <tr>
    <td style="padding:0;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <thead>
          <tr style="background:#fffbeb;border-bottom:2px solid #fbd38d;">
            <th style="padding:10px 12px;text-align:left;font-size:12px;
                       color:#92400e;font-weight:700;text-transform:uppercase;">Hostname</th>
            <th style="padding:10px 12px;text-align:center;font-size:12px;
                       color:#92400e;font-weight:700;text-transform:uppercase;width:80px;">Status</th>
            <th style="padding:10px 12px;text-align:left;font-size:12px;
                       color:#92400e;font-weight:700;text-transform:uppercase;width:200px;">Title</th>
            <th style="padding:10px 12px;text-align:left;font-size:12px;
                       color:#92400e;font-weight:700;text-transform:uppercase;">Keywords</th>
          </tr>
        </thead>
        <tbody>
          {hv_rows}
        </tbody>
      </table>
    </td>
  </tr>
</table>

<!-- ═══════════════════════════════════════════ DNS-ONLY NEW SUBS ══ -->
{"" if not dns_only else f"""
<table width="100%" cellpadding="0" cellspacing="0"
       style="max-width:680px;margin:24px auto 0;background:#ffffff;
              border-radius:16px;overflow:hidden;
              box-shadow:0 2px 16px rgba(0,0,0,0.07);">
  <tr>
    <td style="background:#2d3748;padding:16px 20px;">
      <h2 style="margin:0;font-size:16px;font-weight:700;color:#ffffff;">
        🌐 DNS-Only New Subdomains (no HTTP response)
      </h2>
      <p style="margin:4px 0 0;font-size:12px;color:#a0aec0;">
        Discovered by subfinder — not yet reachable over HTTP/S
      </p>
    </td>
  </tr>
  <tr>
    <td>
      <table width="100%" cellpadding="0" cellspacing="0">
        {dns_rows}
      </table>
    </td>
  </tr>
</table>
"""}

<!-- ═══════════════════════════════════════════ FOOTER ══ -->
<table width="100%" cellpadding="0" cellspacing="0"
       style="max-width:680px;margin:24px auto 32px;">
  <tr>
    <td align="center" style="padding:20px;border-top:1px solid #e2e8f0;">
      <p style="margin:0;font-size:13px;color:#718096;">
        <strong style="color:#1a1a2e;">BugBounty-Recon</strong>
        &nbsp;·&nbsp; Reconnaissance Report
      </p>
      <p style="margin:6px 0 0;font-size:12px;color:#a0aec0;">
        Developed by <strong style="color:#e94560;">Ahmed Wael</strong>
        &nbsp;·&nbsp; Generated automatically via GitHub Actions
      </p>
      <p style="margin:6px 0 0;font-size:11px;color:#cbd5e0;">
        Stay ahead. Stay safe. Happy Hunting. 🎯
      </p>
    </td>
  </tr>
</table>

</body>
</html>"""

    return html


# ---------------------------------------------------------------------------
# Step 9 — Send email
# ---------------------------------------------------------------------------
def send_email_report(
    html_body: str,
    new_count: int,
    active_count: int,
    hv_count: int,
    parts_processed: list[int],
) -> None:
    """
    Dispatch the HTML report via SMTP (STARTTLS).

    Required environment variables:
        SMTP_EMAIL       — sender address (also used as SMTP login)
        SMTP_PASSWORD    — app-specific password
        RECIPIENT_EMAIL  — destination inbox

    Optional:
        SMTP_HOST        — default smtp.gmail.com
        SMTP_PORT        — default 587

    Developer: Ahmed Wael
    """
    smtp_email    = os.environ.get("SMTP_EMAIL", "").strip()
    smtp_password = os.environ.get("SMTP_PASSWORD", "").strip()
    recipient     = os.environ.get("RECIPIENT_EMAIL", "").strip()
    smtp_host     = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()
    smtp_port     = int(os.environ.get("SMTP_PORT", "587"))

    if not all([smtp_email, smtp_password, recipient]):
        log.warning(
            "Email credentials incomplete (SMTP_EMAIL / SMTP_PASSWORD / RECIPIENT_EMAIL). "
            "Skipping email dispatch."
        )
        # Save HTML to disk as a fallback
        report_path = Path("last_report.html")
        report_path.write_text(html_body, encoding="utf-8")
        log.info("HTML report saved locally to: %s", report_path.resolve())
        return

    parts_label = ", ".join(str(p) for p in parts_processed)
    alert_emoji = "🚨" if hv_count > 0 else "📋"
    subject = (
        f"{alert_emoji} [BugBounty-Recon] Parts {parts_label} — "
        f"{new_count} New Subs | {active_count} Active | {hv_count} High-Value"
    )

    # Plain-text fallback
    plain = (
        f"BugBounty-Recon Daily Report — Developed by Ahmed Wael\n"
        f"{'=' * 55}\n"
        f"Parts Processed : {parts_label}\n"
        f"New Subdomains  : {new_count}\n"
        f"Active Hosts    : {active_count}\n"
        f"High-Value Flags: {hv_count}\n"
        f"{'=' * 55}\n"
        "See the HTML version of this email for the full report.\n"
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"BugBounty-Recon <{smtp_email}>"
    msg["To"]      = recipient
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    log.info("Sending HTML report to %s via %s:%d …", recipient, smtp_host, smtp_port)
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(smtp_email, smtp_password)
            srv.sendmail(smtp_email, recipient, msg.as_string())
        log.info("Email report dispatched successfully.")
    except smtplib.SMTPException as exc:
        log.error("SMTP error: %s", exc)
    except OSError as exc:
        log.error("Network error while sending email: %s", exc)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
def main() -> None:
    """
    Full daily recon pipeline orchestrator.

    Reads PARTS environment variable (comma-separated integers, e.g. "1,2,3")
    to determine which part files to process in this run.

    Developer: Ahmed Wael
    """
    # ── Resolve which parts to run ──────────────────────────────────────────
    parts_env = os.environ.get("PARTS", "").strip()
    if not parts_env:
        log.error(
            "PARTS environment variable is not set. "
            "Provide a comma-separated list, e.g. PARTS=1,2,3"
        )
        sys.exit(1)

    try:
        parts_to_run = [int(p.strip()) for p in parts_env.split(",") if p.strip()]
    except ValueError:
        log.error("PARTS must be comma-separated integers. Got: '%s'", parts_env)
        sys.exit(1)

    invalid = [p for p in parts_to_run if not (1 <= p <= TOTAL_PARTS)]
    if invalid:
        log.error(
            "Part numbers must be between 1 and %d. Invalid: %s",
            TOTAL_PARTS,
            invalid,
        )
        sys.exit(1)

    run_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    log.info("=" * 60)
    log.info("BugBounty-Recon  |  Developer: Ahmed Wael")
    log.info("Run timestamp   : %s", run_ts)
    log.info("Parts to process: %s", parts_to_run)
    log.info("=" * 60)

    # ── Pipeline ─────────────────────────────────────────────────────────────
    targets       = load_part_targets(parts_to_run)
    current_subs  = run_subfinder(targets)
    probed_raw    = run_httpx(current_subs)
    probed_hosts  = parse_httpx_results(probed_raw)
    baseline_subs = load_baseline(BASELINE_FILE)
    new_subs      = diff_subdomains(current_subs, baseline_subs)

    # Filter probed results to only those in the new_subs set
    new_active = [h for h in probed_hosts if h["host"] in new_subs]
    high_value  = triage_high_value(new_active)

    log.info(
        "Summary → new: %d | new+active: %d | high-value: %d",
        len(new_subs),
        len(new_active),
        len(high_value),
    )

    # ── Report & Alert ────────────────────────────────────────────────────────
    if new_subs:
        html_report = generate_html_report(
            new_subs      = new_subs,
            active_hosts  = new_active,
            high_value_targets = high_value,
            parts_processed    = parts_to_run,
            run_timestamp      = run_ts,
        )
        send_email_report(
            html_body       = html_report,
            new_count       = len(new_subs),
            active_count    = len(new_active),
            hv_count        = len(high_value),
            parts_processed = parts_to_run,
        )
        update_baseline(BASELINE_FILE, new_subs, baseline_subs)
    else:
        log.info("✅ No new subdomains discovered in this batch. Baseline unchanged.")

    log.info("=" * 60)
    log.info("Batch complete — Parts %s", parts_to_run)
    log.info("=" * 60)


if __name__ == "__main__":
    main()
