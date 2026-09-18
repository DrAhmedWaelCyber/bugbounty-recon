#!/usr/bin/env python3
"""
main.py — BugBounty-Recon Daily Reconnaissance Pipeline
=========================================================
Developer : Ahmed Wael
Purpose   : Orchestrate daily recon across a designated set of part files,
            processing them SEQUENTIALLY with a 3-minute cooldown between
            each part.  After each part completes, a branded HTML email
            report is dispatched immediately.

Pipeline per part
-----------------
  1. Load targets from the pre-split part file.
  2. Discover subdomains with subfinder (all-sources, silent).
  3. Probe discovered subdomains with httpx (active-host detection).
  4. Diff against the persistent baseline → isolate brand-new assets.
  5. Triage new active hosts → priority-ranked high-value targets.
  6. Generate a professional HTML email report.
  7. Dispatch the report via SMTP.
  8. Update the persistent baseline (disk + in-memory) immediately.
  9. Sleep 3 minutes before starting the next part (cooldown).

License   : MIT
"""

import json
import logging
import os
import smtplib
import subprocess
import sys
import tempfile
import threading
import time
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
PARTS_DIR              = Path("parts")
BASELINE_FILE          = Path("baseline_subs.txt")
TOTAL_PARTS            = 63          # 9 parts/day × 7 days = 63-part weekly rotation
COOLDOWN_BETWEEN_PARTS = 180         # 3 minutes between sequential part runs

# Subprocess timeouts (seconds)
SUBFINDER_TIMEOUT = 3600
HTTPX_TIMEOUT_CLI = 3600

# httpx per-run settings
HTTPX_THREADS      = 150   # high concurrency for maximum throughput
HTTPX_HOST_TIMEOUT = 3     # skip unresponsive hosts fast (seconds)
HTTPX_RATE_LIMIT   = 300   # requests/second ceiling

# ── High-value keyword taxonomy ──────────────────────────────────────────────
# Any subdomain whose hostname contains one or more of these tokens is flagged.
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

# Subset considered CRITICAL priority (known sensitive attack surfaces)
CRITICAL_KEYWORDS: frozenset[str] = frozenset([
    "admin", "administrator", "phpmyadmin", "adminer",
    "cpanel", "whm", "webmin", "plesk",
    "jenkins", "gitlab", "grafana", "kibana",
    "confluence", "jira", "sonar",
])


# ===========================================================================
# Utility helpers
# ===========================================================================

def _fmt_duration(seconds: float) -> str:
    """
    Convert raw seconds to a compact, human-readable duration string.

    Examples:  3661 → "1h 01m 01s" | 90 → "1m 30s" | 5 → "5s" | 0.3 → "<1s"

    Developer: Ahmed Wael
    """
    if seconds < 1:
        return "<1s"
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s   = divmod(rem, 60)
    if h:
        return f"{h}h {m:02d}m {s:02d}s"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


# ===========================================================================
# Streaming subprocess helper  (live output + progress ticker)
# ===========================================================================

def _stream_subprocess(
    cmd: list[str],
    timeout_secs: int,
    label: str,
    total_input: int = 0,
    progress_mode: str = "discover",
    progress_every: float = 30.0,
) -> tuple[int, list[str]]:
    """
    Execute *cmd* via Popen and stream stdout + stderr line-by-line in
    real-time so GitHub Actions never shows a frozen log.

    A background progress-ticker thread fires every *progress_every* seconds
    and prints a dynamic snapshot — percentage + ETA for probe mode,
    discovery-rate + timeout headroom for discover mode.

    Threading model
    ---------------
      Main thread   — reads proc.stdout, appends to stdout_lines, flushes.
      Stderr daemon — drains proc.stderr so the OS pipe never deadlocks.
      Watchdog      — kills proc after *timeout_secs* if proc_done isn't set.
      Ticker        — wakes every *progress_every* seconds, logs progress.

    Developer: Ahmed Wael
    """
    stdout_lines: list[str] = []
    timed_out  = threading.Event()
    proc_done  = threading.Event()
    start_time = time.monotonic()

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        encoding="utf-8",
        errors="ignore",
    )

    # ── Watchdog ──────────────────────────────────────────────────────────────
    def _watchdog() -> None:
        if not proc_done.wait(timeout=timeout_secs):
            log.warning("[%s] ⏱ Hard timeout (%s) — killing process.", label, _fmt_duration(timeout_secs))
            timed_out.set()
            proc.kill()

    threading.Thread(target=_watchdog, daemon=True, name=f"{label}-watchdog").start()

    # ── Stderr drain ──────────────────────────────────────────────────────────
    def _drain_stderr() -> None:
        for raw in proc.stderr:
            line = raw.rstrip("\n")
            if line:
                sys.stderr.write(f"  [{label}][stderr] {line}\n")
                sys.stderr.flush()

    threading.Thread(target=_drain_stderr, daemon=True, name=f"{label}-stderr").start()

    # ── Progress ticker ───────────────────────────────────────────────────────
    def _ticker() -> None:
        """
        Generic progress ticker — all values computed from live runtime state.
        No hardcoding: total_input is injected by the caller at invocation time
        from the actual count of loaded targets or subdomains.

        Developer: Ahmed Wael
        """
        tick = 0
        while not proc_done.wait(timeout=progress_every):
            tick += 1
            elapsed = time.monotonic() - start_time
            count   = len(stdout_lines)           # GIL-safe list len
            rate_ps = count / elapsed if elapsed > 0 else 0.0
            rate_pm = rate_ps * 60

            if progress_mode == "probe" and total_input > 0:
                pct      = min(count / total_input * 100.0, 100.0)
                remain   = max(total_input - count, 0)
                eta_secs = remain / rate_ps if rate_ps > 0 else None
                eta_str  = _fmt_duration(eta_secs) if eta_secs else "calculating…"
                log.info(
                    "[%s] ⏳ Tick #%d | Elapsed: %s | Probed: %d/%d (%.1f%%) | Rate: %.1f/min | ETA: %s",
                    label, tick, _fmt_duration(elapsed), count, total_input, pct, rate_pm, eta_str,
                )
            else:
                ctx = f" (from {total_input} targets)" if total_input > 0 else ""
                log.info(
                    "[%s] ⏳ Tick #%d | Elapsed: %s | Found: %d subdomains%s | Rate: %.1f/min | Timeout in: %s",
                    label, tick, _fmt_duration(elapsed), count, ctx, rate_pm,
                    _fmt_duration(max(timeout_secs - elapsed, 0)),
                )

    threading.Thread(target=_ticker, daemon=True, name=f"{label}-ticker").start()

    # ── Main thread: stream stdout ────────────────────────────────────────────
    for raw in proc.stdout:
        line = raw.rstrip("\n")
        if line:
            stdout_lines.append(line)
            sys.stdout.write(f"  [{label}] {line}\n")
            sys.stdout.flush()

    proc.wait()
    proc_done.set()

    if timed_out.is_set():
        raise subprocess.TimeoutExpired(cmd, timeout_secs)

    return proc.returncode, stdout_lines


# ===========================================================================
# Step 1 — Load targets from part files
# ===========================================================================

def load_part_targets(part_numbers: list[int]) -> list[str]:
    """
    Read and deduplicate targets from the pre-split part files.

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
            ln.strip().lower()
            for ln in part_file.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        before = len(all_targets)
        for ln in lines:
            if ln not in seen:
                seen.add(ln)
                all_targets.append(ln)

        log.info("Part %02d: %d targets  (%s)", num, len(all_targets) - before, part_file)

    log.info("Total unique targets across parts %s: %d", part_numbers, len(all_targets))
    return all_targets


# ===========================================================================
# Step 2 — Subfinder  (live-streaming, discover mode)
# ===========================================================================

def run_subfinder(targets: list[str]) -> set[str]:
    """
    Write targets to a temp file and invoke subfinder (silent / all-sources).
    Each discovered subdomain streams to the log as it is found.

    Developer: Ahmed Wael
    """
    if not targets:
        log.warning("[subfinder] No targets provided. Skipping.")
        return set()

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="sf_targets_") as tf:
        tf.write("\n".join(targets))
        targets_path = tf.name

    log.info("─" * 55)
    log.info("[subfinder] Starting — %d targets", len(targets))
    log.info("─" * 55)

    try:
        rc, lines = _stream_subprocess(
            cmd=["subfinder", "-dL", targets_path, "-silent", "-all"],
            timeout_secs=SUBFINDER_TIMEOUT,
            label="subfinder",
            total_input=len(targets),
            progress_mode="discover",
            progress_every=30.0,
        )
        if rc != 0:
            log.warning("[subfinder] Non-zero exit: %d", rc)
        discovered = {ln.strip().lower() for ln in lines if ln.strip()}
        log.info("[subfinder] Done — %d unique subdomains discovered.", len(discovered))
        return discovered
    except FileNotFoundError:
        log.error("[subfinder] Binary not found. Is it installed and on PATH?")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        log.error("[subfinder] Timed out after %s.", _fmt_duration(SUBFINDER_TIMEOUT))
        sys.exit(1)
    finally:
        Path(targets_path).unlink(missing_ok=True)


# ===========================================================================
# Step 3 — httpx  (live-streaming JSON, probe mode)
# ===========================================================================

def run_httpx(subdomains: set[str]) -> list[dict]:
    """
    Probe *subdomains* with httpx at maximum speed.

    Speed flags
    -----------
    -threads 150  : 150 concurrent probes
    -timeout 3    : give each host exactly 3 s — dead hosts are skipped instantly
    -retries 0    : zero retries — never waste time on a host that didn't respond
    -no-color     : strip ANSI escape codes from any stderr output
    -silent       : suppress httpx's own progress banner

    Filtering flags
    ---------------
    -mc  : only emit JSON for these status codes; everything else (404, 410,
           0, etc.) is discarded at the tool level — parse_httpx_results()
           therefore receives only live hosts

    Returns a list of raw JSON result dicts (one per responding host).
    Gracefully degrades to empty list if httpx is not installed.

    Developer: Ahmed Wael
    """
    if not subdomains:
        log.info("[httpx] No subdomains to probe.")
        return []

    # Codes we want httpx to report. Mirrors ACTIVE_CODES in parse_httpx_results()
    # exactly so there is no gap between tool-level and parser-level filtering.
    MATCH_CODES = "200,201,204,301,302,303,307,308,401,403,405,500,502,503"

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, prefix="hx_input_") as tf:
        tf.write("\n".join(sorted(subdomains)))
        input_path = tf.name

    log.info("─" * 55)
    log.info(
        "[httpx] Starting — %d subdomains  threads=%d  timeout=%ds  retries=0",
        len(subdomains), HTTPX_THREADS, HTTPX_HOST_TIMEOUT,
    )
    log.info("─" * 55)

    results: list[dict] = []
    try:
        rc, lines = _stream_subprocess(
            cmd=[
                "httpx",
                "-l",          input_path,
                "-json",                      # structured output, one line per host
                "-silent",                    # suppress httpx's progress banner
                "-no-color",                  # strip ANSI codes from stderr
                "-sc",                        # include status code in JSON
                "-title",                     # include page title in JSON
                "-mc",         MATCH_CODES,   # tool-level dead-code filter
                "-threads",    str(HTTPX_THREADS),
                "-timeout",    str(HTTPX_HOST_TIMEOUT),
                "-retries",    "0",           # never retry — skip dead hosts fast
            ],
            timeout_secs=HTTPX_TIMEOUT_CLI,
            label="httpx",
            total_input=len(subdomains),
            progress_mode="probe",
            progress_every=30.0,
        )
        if rc != 0:
            log.warning("[httpx] Non-zero exit: %d", rc)

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        log.info("[httpx] Done — %d active hosts confirmed.", len(results))
    except FileNotFoundError:
        log.warning("[httpx] Binary not found — probing skipped. "
                    "Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
    except subprocess.TimeoutExpired:
        log.error("[httpx] Timed out after %s.", _fmt_duration(HTTPX_TIMEOUT_CLI))
    finally:
        Path(input_path).unlink(missing_ok=True)

    return results




# ===========================================================================
# Step 4 — Normalise httpx results
# ===========================================================================

def parse_httpx_results(raw_results: list[dict]) -> list[dict]:
    """
    Normalise raw httpx JSON objects into a consistent dict schema.

    Filtering strategy
    ------------------
    Since httpx is already called with -mc (match-codes), the tool discards
    404s and other dead codes before emitting any JSON.  The parser therefore
    uses a minimal BLOCKLIST approach — only explicitly dead codes are dropped
    here.  Using a closed ALLOWLIST (as before) caused valid responses with
    codes like 202, 206, 429 to be silently discarded, resulting in 0 results.

    Gates (in order)
    ----------------
    1. Empty-host gate   — drop entries with no resolvable hostname.
    2. Dead-code gate    — drop only: 0 (no response), 404 (not found),
                           410 (gone).  Every other code passes through.
    3. Noise gate        — drop purely-numeric first labels (CDN IPs leaked as
                           hostnames) and 32+ hex-char UUID/hash labels.
                           One-character labels (a.example.com) are VALID and
                           are no longer dropped.

    Returned keys: host, url, status_code, title, server

    Developer: Ahmed Wael
    """
    # Only these codes are truly dead — everything else from httpx is live
    DEAD_CODES: frozenset[int] = frozenset([0, 404, 410])

    parsed: list[dict] = []
    dropped_dead  = 0
    dropped_noise = 0

    for item in raw_results:
        # ── 1. Normalise host ────────────────────────────────────────────────
        host = (item.get("input") or item.get("host") or "").strip().lower()
        if "://" in host:
            host = host.split("://", 1)[1].rstrip("/")
        # Strip port suffix for label inspection (e.g. "api.example.com:8080")
        host_no_port = host.split(":")[0].strip()
        if not host_no_port:
            dropped_noise += 1
            continue

        # ── 2. Dead-code gate (blocklist only) ──────────────────────────────
        # httpx ≥ 2.x emits "status_code" (underscore); older builds used
        # "status-code" (hyphen).  Check both so neither format causes a
        # silent miss that returns 0 and drops every host as "dead".
        raw_code = item.get("status_code") or item.get("status-code") or 0
        try:
            code = int(raw_code)
        except (ValueError, TypeError):
            code = 0
        if code in DEAD_CODES:
            dropped_dead += 1
            continue

        # ── 3. Noise gate ────────────────────────────────────────────────────
        labels      = host_no_port.split(".")
        first_label = labels[0] if labels else ""

        # Purely-numeric first label — leaked IP-style CDN hostnames
        # (e.g. "1234.cdn.example.com").  Note: one-character labels like
        # "a.example.com" are intentionally NOT dropped — they are valid.
        if first_label.isdigit():
            dropped_noise += 1
            continue

        # 32+ hex-character first label = UUID / hash auto-generated by CDN
        if len(first_label) >= 32 and all(c in "0123456789abcdef-" for c in first_label):
            dropped_noise += 1
            continue

        parsed.append({
            "host":        host_no_port,
            "url":         item.get("url", ""),
            "status_code": code,
            "title":       (item.get("title") or "").strip(),
            "server":      (item.get("webserver") or "").strip(),
        })

    log.info(
        "parse_httpx_results: %d kept | %d dropped (dead code) | %d dropped (noise)",
        len(parsed), dropped_dead, dropped_noise,
    )
    return parsed




# ===========================================================================
# Step 5 — Baseline management
# ===========================================================================

def load_baseline(path: Path) -> set[str]:
    """Load persistent baseline into a set. Returns empty set if file absent."""
    if not path.exists():
        log.info("No baseline file at '%s'. Starting fresh.", path)
        return set()
    entries = {
        ln.strip().lower()
        for ln in path.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    }
    log.info("Baseline loaded: %d known subdomains.", len(entries))
    return entries


def update_baseline(path: Path, new_subs: set[str], existing: set[str]) -> None:
    """Merge *new_subs* into *existing*, write sorted to *path*."""
    merged = existing | new_subs
    path.write_text(
        "# BugBounty-Recon baseline — auto-managed by main.py\n"
        "# Developer: Ahmed Wael\n"
        + "\n".join(sorted(merged)) + "\n",
        encoding="utf-8",
    )
    log.info("Baseline updated: %d total (+%d new).", len(merged), len(new_subs))


# ===========================================================================
# Step 6 — Diff
# ===========================================================================

def diff_subdomains(current: set[str], baseline: set[str]) -> set[str]:
    """Return subdomains in *current* but absent from *baseline*."""
    new_subs = current - baseline
    log.info("Diff: %d current | %d baseline | %d NEW", len(current), len(baseline), len(new_subs))
    return new_subs


# ===========================================================================
# Step 7 — High-value triage with priority ranking
# ===========================================================================

def _get_priority(host_info: dict) -> str:
    """
    Assign a three-tier severity label to a flagged host.

    CRITICAL — matched a known high-impact keyword AND serves a live 200 response.
    HIGH     — matched a critical keyword (any status) or 200 with any HV keyword.
    MEDIUM   — any other HV keyword match.

    Developer: Ahmed Wael
    """
    kws  = {kw.lower() for kw in host_info.get("keywords", [])}
    code = host_info.get("status_code", 0)
    crit = bool(kws & CRITICAL_KEYWORDS)

    if crit and code == 200:
        return "CRITICAL"
    if crit or code == 200:
        return "HIGH"
    return "MEDIUM"


def triage_high_value(probed_hosts: list[dict]) -> list[dict]:
    """
    Filter *probed_hosts* for high-value keyword matches, enrich with priority,
    and return sorted CRITICAL → HIGH → MEDIUM, then by status code.

    Belt-and-suspenders: any host with a dead/404/0 status code is explicitly
    skipped here even if it somehow bypassed parse_httpx_results filtering.

    Developer: Ahmed Wael
    """
    # Codes that are meaningless for manual inspection
    _DEAD: frozenset[int] = frozenset([0, 400, 404, 410])

    flagged: list[dict] = []
    for h in probed_hosts:
        code = h.get("status_code", 0)
        # Hard reject — dead endpoints have no value in a triage report
        if code in _DEAD:
            continue
        matched = [kw for kw in HIGH_VALUE_KEYWORDS if kw in h["host"].lower()]
        if matched:
            enriched = {**h, "keywords": matched}
            enriched["priority"] = _get_priority(enriched)
            flagged.append(enriched)

    _order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    flagged.sort(key=lambda x: (_order.get(x.get("priority", "MEDIUM"), 2), -x.get("status_code", 0)))
    log.info("High-value triage: %d / %d active hosts flagged.", len(flagged), len(probed_hosts))
    return flagged



# ===========================================================================
# Step 8 — HTML report generation
# ===========================================================================

# ── Inline badge helpers ──────────────────────────────────────────────────────

def _status_badge(code: int) -> str:
    """Colour-coded HTTP status badge (inline CSS for email compatibility)."""
    if code == 0:
        clr, bg = "#6b7280", "#f3f4f6"
    elif 200 <= code < 300:
        clr, bg = "#065f46", "#d1fae5"
    elif 300 <= code < 400:
        clr, bg = "#92400e", "#fef3c7"
    elif 400 <= code < 500:
        clr, bg = "#991b1b", "#fee2e2"
    else:
        clr, bg = "#5b21b6", "#ede9fe"
    label = str(code) if code else "N/A"
    return (
        f'<span style="display:inline-block;padding:2px 10px;border-radius:20px;'
        f'font-size:12px;font-weight:700;color:{clr};background:{bg};">{label}</span>'
    )


def _priority_badge(priority: str) -> str:
    """Severity-tier badge for high-value targets."""
    styles = {
        "CRITICAL": ("#fff", "#dc2626", "⚠ CRITICAL"),
        "HIGH":     ("#fff", "#ea580c", "↑ HIGH"),
        "MEDIUM":   ("#1c1917", "#f59e0b", "▲ MEDIUM"),
    }
    fg, bg, label = styles.get(priority, ("#1c1917", "#f59e0b", "▲ MEDIUM"))
    return (
        f'<span style="display:inline-block;padding:2px 10px;border-radius:4px;'
        f'font-size:11px;font-weight:800;letter-spacing:0.6px;'
        f'color:{fg};background:{bg};">{label}</span>'
    )


def _keyword_tags(keywords: list[str]) -> str:
    """Render matched keyword tokens as small inline pills."""
    tags = []
    for kw in keywords[:6]:
        tags.append(
            f'<span style="display:inline-block;margin:1px 2px;padding:1px 7px;'
            f'border-radius:20px;font-size:11px;font-weight:600;'
            f'color:#92400e;background:#fef3c7;">{escape(kw)}</span>'
        )
    return "".join(tags)


# ── Section builders ──────────────────────────────────────────────────────────

def _section_header(icon: str, title: str, count: int, bg: str, fg: str = "#fff") -> str:
    return f"""
    <tr>
      <td style="background:{bg};padding:14px 20px;border-radius:10px 10px 0 0;">
        <table width="100%" cellpadding="0" cellspacing="0">
          <tr>
            <td style="font-size:16px;font-weight:700;color:{fg};">
              {icon} {escape(title)}
            </td>
            <td align="right">
              <span style="background:rgba(255,255,255,0.2);color:{fg};
                           font-size:13px;font-weight:700;padding:3px 12px;
                           border-radius:20px;">{count:,}</span>
            </td>
          </tr>
        </table>
      </td>
    </tr>"""


def _build_report_header(part_num: int, targets_count: int, run_ts: str) -> str:
    return f"""
<table width="100%" cellpadding="0" cellspacing="0"
       style="background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 55%,#0f172a 100%);">
  <tr>
    <td align="center" style="padding:40px 24px 32px;">
      <table style="max-width:680px;" cellpadding="0" cellspacing="0">
        <tr>
          <td align="center">
            <!-- Logo mark -->
            <div style="width:56px;height:56px;border-radius:16px;
                        background:linear-gradient(135deg,#6366f1,#8b5cf6);
                        line-height:56px;text-align:center;font-size:28px;
                        margin:0 auto 16px;box-shadow:0 4px 20px rgba(99,102,241,.4);">🔍</div>
            <h1 style="margin:0;font-size:26px;font-weight:900;color:#f1f5f9;
                        letter-spacing:-0.5px;">BugBounty-Recon</h1>
            <p style="margin:6px 0 0;font-size:14px;color:#94a3b8;">
              Daily Intelligence Report &nbsp;·&nbsp;
              <strong style="color:#818cf8;">Part {part_num:02d} / {TOTAL_PARTS}</strong>
            </p>
            <p style="margin:8px 0 0;font-size:12px;color:#64748b;">
              {escape(run_ts)} &nbsp;·&nbsp;
              {targets_count:,} targets processed &nbsp;·&nbsp;
              Developed by <strong style="color:#a5b4fc;">Ahmed Wael</strong>
            </p>
          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>"""


def _build_stat_cards(
    total_new: int, total_active: int, total_hv: int, baseline_total: int
) -> str:
    def _card(value: str, label: str, color: str, icon: str, sub: str = "") -> str:
        return f"""
        <td width="25%" style="padding:6px;">
          <table width="100%" cellpadding="0" cellspacing="0"
                 style="background:#fff;border-radius:12px;
                        box-shadow:0 2px 12px rgba(0,0,0,0.07);
                        border-top:4px solid {color};">
            <tr>
              <td align="center" style="padding:18px 8px 20px;">
                <div style="font-size:24px;margin-bottom:6px;">{icon}</div>
                <div style="font-size:32px;font-weight:900;color:#0f172a;
                            letter-spacing:-1px;">{value}</div>
                <div style="font-size:11px;color:#64748b;font-weight:700;
                            text-transform:uppercase;letter-spacing:0.8px;
                            margin-top:4px;">{label}</div>
                {"<div style='font-size:10px;color:#94a3b8;margin-top:2px;'>" + sub + "</div>" if sub else ""}
              </td>
            </tr>
          </table>
        </td>"""

    hv_color = "#dc2626" if total_hv > 0 else "#6b7280"
    return f"""
<table width="100%" cellpadding="0" cellspacing="0"
       style="max-width:700px;margin:20px auto 0;">
  <tr>
    {_card(f"{total_new:,}",    "New Subdomains",  "#6366f1", "🌐", "vs baseline")}
    {_card(f"{total_active:,}", "Active HTTP",     "#10b981", "✅", "responded")}
    {_card(f"{total_hv:,}",     "High-Value",      hv_color,  "🚨", "flagged")}
    {_card(f"{baseline_total:,}", "Total Known",   "#94a3b8", "📚", "in baseline")}
  </tr>
</table>"""


def _build_hv_section(high_value: list[dict]) -> str:
    if not high_value:
        return ""

    rows = ""
    for hv in high_value:
        priority = hv.get("priority", "MEDIUM")
        row_bg   = {"CRITICAL": "#fff5f5", "HIGH": "#fff7ed", "MEDIUM": "#fffbeb"}.get(priority, "#fffbeb")
        rows += f"""
        <tr style="background:{row_bg};border-bottom:1px solid #fde8d8;">
          <td style="padding:10px 14px;white-space:nowrap;">{_priority_badge(priority)}</td>
          <td style="padding:10px 8px;font-size:13px;color:#1e293b;word-break:break-all;">
            <a href="https://{escape(hv['host'])}" style="color:#dc2626;font-weight:600;
               text-decoration:none;">🎯 {escape(hv['host'])}</a>
          </td>
          <td style="padding:10px 8px;text-align:center;white-space:nowrap;">{_status_badge(hv.get('status_code',0))}</td>
          <td style="padding:10px 8px;font-size:12px;color:#475569;max-width:160px;
                     overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
            {escape(hv.get('title', '') or '—')}</td>
          <td style="padding:10px 8px;">{_keyword_tags(hv.get('keywords', []))}</td>
        </tr>"""

    th = """<tr style="background:#fef2f2;border-bottom:2px solid #fca5a5;">
      <th style="padding:10px 14px;font-size:11px;color:#991b1b;font-weight:700;
                 text-transform:uppercase;text-align:left;white-space:nowrap;">Priority</th>
      <th style="padding:10px 8px;font-size:11px;color:#991b1b;font-weight:700;
                 text-transform:uppercase;text-align:left;">Hostname</th>
      <th style="padding:10px 8px;font-size:11px;color:#991b1b;font-weight:700;
                 text-transform:uppercase;text-align:center;">Status</th>
      <th style="padding:10px 8px;font-size:11px;color:#991b1b;font-weight:700;
                 text-transform:uppercase;text-align:left;">Title</th>
      <th style="padding:10px 8px;font-size:11px;color:#991b1b;font-weight:700;
                 text-transform:uppercase;text-align:left;">Keywords</th>
    </tr>"""

    return f"""
<table width="100%" cellpadding="0" cellspacing="0"
       style="max-width:700px;margin:24px auto 0;background:#fff;
              border-radius:12px;overflow:hidden;
              border:2px solid #fca5a5;
              box-shadow:0 4px 20px rgba(220,38,38,.10);">
  {_section_header("🚨", "High-Value Targets — Manual Inspection Required",
                   len(high_value), "linear-gradient(90deg,#dc2626,#b91c1c)")}
  <tr>
    <td style="padding:0;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <thead>{th}</thead>
        <tbody>{rows}</tbody>
      </table>
    </td>
  </tr>
</table>"""


def _build_active_table(new_active: list[dict], high_value: list[dict]) -> str:
    """
    Render the active-HTTP-hosts section.

    Design principles
    -----------------
    • Sort 200s first, then 403/401 (auth-gated), then redirects, then 5xx.
    • Deduplicate on the parent domain — if 10 sub-subdomains of the same
      parent all respond, show only the 3 highest-status-code ones to avoid
      visual spam; the count of suppressed entries is shown in the row.
    • High-value hosts get a left-border accent (⚡), not a full background wash.
    • Cap at 150 rows; overflow count shown with a note to check baseline_subs.txt.

    Developer: Ahmed Wael
    """
    hv_hosts = {hv["host"] for hv in high_value}

    # Sort: 200 > 403/401 > 3xx > 5xx
    def _sort_key(h: dict) -> tuple:
        code = h.get("status_code", 0)
        order = {200: 0, 201: 0, 204: 0, 403: 1, 401: 1, 405: 1,
                 301: 2, 302: 2, 307: 2, 308: 2, 303: 2,
                 500: 3, 502: 3, 503: 3}
        return (order.get(code, 9), h.get("host", ""))

    sorted_active = sorted(new_active, key=_sort_key)

    # Deduplicate per parent domain — keep top 3 per parent
    from collections import defaultdict
    by_parent: dict[str, list[dict]] = defaultdict(list)
    for h in sorted_active:
        parts = h["host"].split(".")
        parent = ".".join(parts[-2:]) if len(parts) >= 2 else h["host"]
        by_parent[parent].append(h)

    deduped: list[dict] = []
    suppressed_counts: dict[str, int] = {}
    MAX_PER_PARENT = 3
    for parent, hosts in by_parent.items():
        deduped.extend(hosts[:MAX_PER_PARENT])
        if len(hosts) > MAX_PER_PARENT:
            suppressed_counts[parent] = len(hosts) - MAX_PER_PARENT

    # Final cap
    CAP = 150
    display = deduped[:CAP]
    total_suppressed_rows = max(len(new_active) - len(display), 0)

    if not display:
        rows = """<tr><td colspan="3" style="padding:24px;text-align:center;
                   color:#94a3b8;font-style:italic;">
                   No active HTTP/S hosts detected in this batch.</td></tr>"""
    else:
        rows = ""
        for i, h in enumerate(display):
            is_hv    = h["host"] in hv_hosts
            row_bg   = "#fff" if i % 2 == 0 else "#f8fafc"
            lborder  = "border-left:4px solid #f59e0b;" if is_hv else "border-left:4px solid transparent;"
            hv_icon  = "⚡ " if is_hv else ""
            title    = escape(h.get("title", "") or "")
            server   = escape(h.get("server", "") or "")
            subtitle = " · ".join(filter(None, [server, title]))[:80]
            rows += f"""
        <tr style="background:{row_bg};border-bottom:1px solid #e2e8f0;{lborder}">
          <td style="padding:10px 14px;">
            <div style="font-size:13px;font-weight:600;color:#0f172a;">
              {hv_icon}<a href="https://{escape(h['host'])}"
                style="color:#3730a3;text-decoration:none;">{escape(h['host'])}</a>
            </div>
            {"<div style='font-size:11px;color:#94a3b8;margin-top:2px;'>" + subtitle + "</div>" if subtitle else ""}
          </td>
          <td style="padding:10px 8px;text-align:center;white-space:nowrap;width:70px;">
            {_status_badge(h.get("status_code", 0))}
          </td>
        </tr>"""

        # Show parent-domain suppression notices inline
        for parent, cnt in suppressed_counts.items():
            rows += f"""
        <tr style="background:#f0f9ff;border-bottom:1px solid #e0f2fe;">
          <td colspan="2" style="padding:6px 14px;font-size:11px;color:#0369a1;
              font-style:italic;">+ {cnt} more under <strong>{escape(parent)}</strong>
              — see baseline_subs.txt</td>
        </tr>"""

        if total_suppressed_rows > 0:
            rows += f"""<tr><td colspan="2" style="padding:10px 14px;font-size:12px;
                        color:#64748b;text-align:center;background:#f8fafc;
                        border-top:2px dashed #cbd5e1;">
                        {total_suppressed_rows:,} additional hosts not shown — full list in baseline_subs.txt
                        </td></tr>"""

    th = """<tr style="background:#f1f5f9;border-bottom:2px solid #cbd5e1;">
      <th style="padding:10px 14px;font-size:11px;color:#475569;font-weight:700;
                 text-transform:uppercase;text-align:left;">Hostname / Title</th>
      <th style="padding:10px 8px;font-size:11px;color:#475569;font-weight:700;
                 text-transform:uppercase;text-align:center;width:70px;">Status</th>
    </tr>"""

    return f"""
<table width="100%" cellpadding="0" cellspacing="0"
       style="max-width:700px;margin:24px auto 0;background:#fff;
              border-radius:12px;overflow:hidden;
              box-shadow:0 2px 12px rgba(0,0,0,0.07);">
  {_section_header("✅", "New Active HTTP Hosts",
                   len(new_active), "#059669")}
  <tr>
    <td style="padding:0;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <thead>{th}</thead>
        <tbody>{rows}</tbody>
      </table>
    </td>
  </tr>
</table>"""


def _build_dns_section(dns_only: list[str]) -> str:
    """
    Render the DNS-only discoveries section.

    Groups subdomains by parent domain so the output reads as a structured
    list rather than a flat flood of hundreds of pills.  Shows at most 5
    subdomains per parent, with a "+N more" notice for the rest.

    Developer: Ahmed Wael
    """
    if not dns_only:
        return ""

    from collections import defaultdict
    by_parent: dict[str, list[str]] = defaultdict(list)
    for sub in sorted(dns_only):
        parts = sub.split(".")
        parent = ".".join(parts[-2:]) if len(parts) >= 2 else sub
        by_parent[parent].append(sub)

    MAX_PER_PARENT = 5
    CAP_PARENTS    = 80   # max parent-domain groups shown

    groups_html = ""
    for parent in sorted(by_parent)[:CAP_PARENTS]:
        subs = by_parent[parent]
        shown = subs[:MAX_PER_PARENT]
        extra = len(subs) - len(shown)

        pills = "".join(
            f'<span style="display:inline-block;margin:2px 3px;padding:2px 9px;'
            f'border-radius:20px;font-size:11px;color:#1e40af;'
            f'background:#dbeafe;white-space:nowrap;">{escape(s)}</span>'
            for s in shown
        )
        more = (
            f'<span style="display:inline-block;margin:2px 3px;padding:2px 9px;'
            f'border-radius:20px;font-size:11px;color:#64748b;'
            f'background:#f1f5f9;white-space:nowrap;">+{extra} more</span>'
            if extra else ""
        )
        groups_html += f"""
      <tr style="border-bottom:1px solid #e2e8f0;">
        <td style="padding:8px 14px;vertical-align:top;white-space:nowrap;
                   width:160px;font-size:12px;font-weight:700;color:#334155;">
          {escape(parent)}
          <div style="font-size:10px;color:#94a3b8;font-weight:400;">
            {len(subs)} sub{'' if len(subs)==1 else 's'}
          </div>
        </td>
        <td style="padding:8px 8px 8px 0;">{pills}{more}</td>
      </tr>"""

    hidden_parents = max(len(by_parent) - CAP_PARENTS, 0)
    overflow = (
        f'<tr><td colspan="2" style="padding:8px 14px;font-size:11px;color:#94a3b8;'
        f'font-style:italic;">… and {hidden_parents} more parent domains — '
        f'see baseline_subs.txt</td></tr>'
        if hidden_parents else ""
    )

    return f"""
<table width="100%" cellpadding="0" cellspacing="0"
       style="max-width:700px;margin:24px auto 0;background:#fff;
              border-radius:12px;overflow:hidden;
              box-shadow:0 2px 12px rgba(0,0,0,0.07);">
  {_section_header("🌐", "New DNS Discoveries (no HTTP response)",
                   len(dns_only), "#2563eb")}
  <tr>
    <td style="padding:0;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tbody>{groups_html}{overflow}</tbody>
      </table>
    </td>
  </tr>
</table>"""



def _build_footer(part_num: int, run_ts: str) -> str:
    return f"""
<table width="100%" cellpadding="0" cellspacing="0"
       style="max-width:700px;margin:24px auto 36px;">
  <tr>
    <td style="border-top:2px solid #e2e8f0;padding:24px 0 0;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td>
            <p style="margin:0;font-size:13px;font-weight:700;color:#0f172a;">
              BugBounty-Recon
            </p>
            <p style="margin:4px 0 0;font-size:12px;color:#94a3b8;">
              Reconnaissance Intelligence Report &nbsp;·&nbsp; Part {part_num:02d}/{TOTAL_PARTS}
            </p>
          </td>
          <td align="right">
            <p style="margin:0;font-size:12px;color:#64748b;">
              Developed by <strong style="color:#6366f1;">Ahmed Wael</strong>
            </p>
            <p style="margin:4px 0 0;font-size:11px;color:#94a3b8;">
              {escape(run_ts)} &nbsp;·&nbsp; GitHub Actions
            </p>
          </td>
        </tr>
      </table>
      <p style="margin:14px 0 0;font-size:11px;color:#cbd5e1;text-align:center;">
        Stay ahead. Stay safe. Happy Hunting. 🎯
      </p>
    </td>
  </tr>
</table>"""


def generate_html_report(results: dict, baseline_total: int) -> str:
    """
    Compose a fully self-contained, responsive HTML email report from the
    results dict produced by process_single_part().

    Sections (in order):
      1. Dark gradient header  — tool name, part info, timestamp, attribution
      2. Metric cards          — new subs / active hosts / high-value / baseline
      3. High-Value Targets    — priority-ranked table (CRITICAL → HIGH → MEDIUM)
      4. New Active HTTP Hosts — status-coded table, capped at 250 rows
      5. DNS-Only Discoveries  — pill display of non-HTTP new subdomains
      6. Footer                — developer credit, timestamp

    Developer: Ahmed Wael
    """
    part_num      = results["part_num"]
    new_subs      = results["new_subs"]
    new_active    = results["new_active"]
    high_value    = results["high_value"]
    targets_count = results["targets_count"]
    run_ts        = results.get("run_timestamp", "")

    active_hosts  = {h["host"] for h in new_active}
    dns_only      = sorted(new_subs - active_hosts)

    header  = _build_report_header(part_num, targets_count, run_ts)
    cards   = _build_stat_cards(len(new_subs), len(new_active), len(high_value), baseline_total)
    hv_sec  = _build_hv_section(high_value)
    act_sec = _build_active_table(new_active, high_value)
    dns_sec = _build_dns_section(dns_only)
    footer  = _build_footer(part_num, run_ts)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1.0" />
  <title>BugBounty-Recon Report — Part {part_num:02d} — Ahmed Wael</title>
</head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif;">

{header}

<table width="100%" cellpadding="0" cellspacing="0">
  <tr><td align="center">
    <table style="max-width:700px;width:100%;" cellpadding="0" cellspacing="0">
      <tr><td>{cards}</td></tr>
      <tr><td>{hv_sec}</td></tr>
      <tr><td>{act_sec}</td></tr>
      <tr><td>{dns_sec}</td></tr>
      <tr><td>{footer}</td></tr>
    </table>
  </td></tr>
</table>

</body>
</html>"""


# ===========================================================================
# Step 9 — SMTP email dispatch
# ===========================================================================

def send_email_report(html_body: str, results: dict, baseline_total: int) -> None:
    """
    Send the HTML report via SMTP (STARTTLS) and save it to disk.

    Every step is logged explicitly so GitHub Actions shows exactly what
    happened — no silent failures.

    Required env vars : SMTP_EMAIL, SMTP_PASSWORD, RECIPIENT_EMAIL
    Optional env vars : SMTP_HOST (default smtp.gmail.com), SMTP_PORT (default 587)

    Developer: Ahmed Wael
    """
    smtp_email = os.environ.get("SMTP_EMAIL", "").strip()
    smtp_pass  = os.environ.get("SMTP_PASSWORD", "").strip()
    recipient  = os.environ.get("RECIPIENT_EMAIL", "").strip()
    smtp_host  = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()
    smtp_port_raw = os.environ.get("SMTP_PORT", "587").strip()
    smtp_port     = int(smtp_port_raw) if smtp_port_raw and smtp_port_raw.isdigit() else 587

    part_num = results["part_num"]
    n_new    = len(results["new_subs"])
    n_active = len(results["new_active"])
    n_hv     = len(results["high_value"])

    # ── Always save HTML to disk first so the artifact is never lost ──────────
    report_path = Path(f"last_report_part{part_num:02d}.html")
    try:
        report_path.write_text(html_body, encoding="utf-8")
        log.info("[email] HTML report saved to: %s  (%d bytes)",
                 report_path.resolve(), report_path.stat().st_size)
    except OSError as exc:
        log.error("[email] Failed to write HTML report to disk: %s", exc)

    # ── Pre-flight diagnostics ────────────────────────────────────────────────
    log.info("[email] ── Pre-flight diagnostics ──────────────────────────")
    log.info("[email]   SMTP_HOST      : %s", smtp_host or "(not set)")
    log.info("[email]   SMTP_PORT      : %d", smtp_port)
    log.info("[email]   SMTP_EMAIL     : %s", smtp_email or "(not set — email will NOT be sent)")
    log.info("[email]   SMTP_PASSWORD  : %s", "set ✅" if smtp_pass else "NOT SET ❌")
    log.info("[email]   RECIPIENT      : %s", recipient or "(not set — email will NOT be sent)")
    log.info("[email] ──────────────────────────────────────────────────────")

    # ── Credential gate ───────────────────────────────────────────────────────
    missing = [name for name, val in [
        ("SMTP_EMAIL", smtp_email),
        ("SMTP_PASSWORD", smtp_pass),
        ("RECIPIENT_EMAIL", recipient),
    ] if not val]

    if missing:
        log.warning(
            "[email] Missing required secret(s): %s — "
            "email will NOT be sent. Report saved to disk only.",
            ", ".join(missing),
        )
        return

    # ── Build message ─────────────────────────────────────────────────────────
    alert_flag = "🚨" if n_hv > 0 else "📋"
    subject = (
        f"{alert_flag} [BugBounty-Recon] Part {part_num:02d}/{TOTAL_PARTS} — "
        f"{n_new:,} New Subs | {n_active:,} Active | {n_hv} High-Value"
    )

    plain = (
        f"BugBounty-Recon Daily Report\n"
        f"Developer: Ahmed Wael\n"
        f"{'=' * 50}\n"
        f"Part            : {part_num:02d} / {TOTAL_PARTS}\n"
        f"New Subdomains  : {n_new:,}\n"
        f"Active HTTP     : {n_active:,}\n"
        f"High-Value      : {n_hv}\n"
        f"Total Baseline  : {baseline_total:,}\n"
        f"{'=' * 50}\n"
        "See the HTML version of this email for the full structured report.\n"
    )

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"BugBounty-Recon <{smtp_email}>"
    msg["To"]      = recipient
    msg.attach(MIMEText(plain, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    log.info("[email] Subject  : %s", subject)
    log.info("[email] To       : %s", recipient)
    log.info("[email] Payload  : %d bytes (HTML body)", len(html_body))

    # ── SMTP send — context manager guarantees connection is live before use ──
    # Root cause of "please run connect() first": manually creating smtplib.SMTP()
    # and then calling methods across a partial failure leaves the object in an
    # uninitialised state.  Using `with smtplib.SMTP(...) as srv:` ensures the
    # TCP connection is established and __enter__ completes before any method
    # call, and __exit__ always calls quit() cleanly.
    try:
        log.info("[email] Connecting to %s:%d …", smtp_host, smtp_port)
        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as srv:
            log.info("[email] EHLO …")
            srv.ehlo()

            log.info("[email] STARTTLS …")
            srv.starttls()

            # RFC 3207 §4.2 — re-identify after TLS handshake; many servers
            # reject LOGIN without a second EHLO issued post-TLS.
            log.info("[email] EHLO (post-TLS) …")
            srv.ehlo()

            log.info("[email] LOGIN …")
            srv.login(smtp_email, smtp_pass)

            log.info("[email] SENDMAIL …")
            rejected = srv.sendmail(smtp_email, [recipient], msg.as_string())

        if rejected:
            log.warning("[email] Delivery rejected for addresses: %s", rejected)
        else:
            log.info("[email] ✅ Email dispatched successfully (Part %02d).", part_num)

    except smtplib.SMTPAuthenticationError as exc:
        log.error(
            "[email] ❌ Authentication failed (code %s): %s\n"
            "  → Check SMTP_EMAIL and SMTP_PASSWORD secrets.\n"
            "  → For Gmail, use an App Password (not your account password).\n"
            "  → Generate one at: https://myaccount.google.com/apppasswords",
            exc.smtp_code, exc.smtp_error,
        )
    except smtplib.SMTPConnectError as exc:
        log.error(
            "[email] ❌ Connection refused to %s:%d (code %s): %s\n"
            "  → Check SMTP_HOST and SMTP_PORT secrets.",
            smtp_host, smtp_port, exc.smtp_code, exc.smtp_error,
        )
    except smtplib.SMTPRecipientsRefused as exc:
        log.error("[email] ❌ Recipient address refused: %s", exc.recipients)
    except smtplib.SMTPException as exc:
        log.error("[email] ❌ SMTP protocol error: %s  (type: %s)",
                  exc, type(exc).__name__)
    except TimeoutError:
        log.error("[email] ❌ Connection timed out to %s:%d", smtp_host, smtp_port)
    except OSError as exc:
        log.error("[email] ❌ Network/OS error: %s  (errno %s)", exc, exc.errno)
    except Exception as exc:                        # last-resort catch-all
        log.error("[email] ❌ Unexpected error during send: %s  (type: %s)",
                  exc, type(exc).__name__)


# ===========================================================================
# Per-part pipeline wrapper
# ===========================================================================

def process_single_part(
    part_num: int,
    baseline_subs: set[str],
    run_timestamp: str,
) -> dict:
    """
    Run the complete reconnaissance pipeline for one part file.

    Returns a results dict containing all data needed for reporting and
    baseline updates.  The caller is responsible for committing the baseline
    after calling this function.

    Developer: Ahmed Wael
    """
    targets = load_part_targets([part_num])

    if not targets:
        log.warning("Part %02d: no targets found in file — skipping.", part_num)
        return {
            "part_num":      part_num,
            "targets_count": 0,
            "current_subs":  set(),
            "new_subs":      set(),
            "new_active":    [],
            "high_value":    [],
            "run_timestamp": run_timestamp,
            "skipped":       True,
        }

    current_subs  = run_subfinder(targets)
    probed_raw    = run_httpx(current_subs)
    probed_hosts  = parse_httpx_results(probed_raw)
    new_subs      = diff_subdomains(current_subs, baseline_subs)
    new_active    = [h for h in probed_hosts if h["host"] in new_subs]
    high_value    = triage_high_value(new_active)

    return {
        "part_num":      part_num,
        "targets_count": len(targets),
        "current_subs":  current_subs,
        "new_subs":      new_subs,
        "new_active":    new_active,
        "high_value":    high_value,
        "run_timestamp": run_timestamp,
        "skipped":       False,
    }


# ===========================================================================
# Entrypoint — sequential multi-part orchestrator
# ===========================================================================

def main() -> None:
    """
    Orchestrate sequential reconnaissance across all assigned part files.

    Environment variables
    ---------------------
    PARTS            : comma-separated part numbers, e.g. "1,2,3,4,5,6,7,8,9"
    SMTP_EMAIL       : sender address
    SMTP_PASSWORD    : SMTP app password
    RECIPIENT_EMAIL  : report inbox
    SMTP_HOST        : (optional) SMTP server — default smtp.gmail.com
    SMTP_PORT        : (optional) SMTP port    — default 587

    Execution flow (per part)
    -------------------------
      load targets → subfinder → httpx → diff → triage
      → HTML report → email → update baseline
      → 3-minute cooldown (except after final part)

    Developer: Ahmed Wael
    """
    parts_env = os.environ.get("PARTS", "").strip()
    if not parts_env:
        log.error("PARTS env var not set. Provide e.g. PARTS=1,2,3,4,5,6,7,8,9")
        sys.exit(1)

    try:
        parts_to_run = [int(p.strip()) for p in parts_env.split(",") if p.strip()]
    except ValueError:
        log.error("PARTS must be comma-separated integers. Got: '%s'", parts_env)
        sys.exit(1)

    invalid = [p for p in parts_to_run if not 1 <= p <= TOTAL_PARTS]
    if invalid:
        log.error("Part numbers out of range 1-%d: %s", TOTAL_PARTS, invalid)
        sys.exit(1)

    run_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    log.info("=" * 65)
    log.info("BugBounty-Recon  |  Developer: Ahmed Wael")
    log.info("Run timestamp    : %s", run_ts)
    log.info("Parts to process : %s  (%d total)", parts_to_run, len(parts_to_run))
    log.info("Cooldown between : %s", _fmt_duration(COOLDOWN_BETWEEN_PARTS))
    log.info("=" * 65)

    baseline = load_baseline(BASELINE_FILE)
    grand_total_new = 0

    for idx, part_num in enumerate(parts_to_run):
        log.info("")
        log.info("▶▶▶  PART %02d  (%d of %d)  ◀◀◀", part_num, idx + 1, len(parts_to_run))
        log.info("")

        results = process_single_part(part_num, baseline, run_ts)

        if results["skipped"]:
            log.info("Part %02d skipped.", part_num)

        elif results["new_subs"]:
            n_new = len(results["new_subs"])
            n_hv  = len(results["high_value"])
            log.info(
                "Part %02d: %d new | %d active | %d high-value",
                part_num, n_new, len(results["new_active"]), n_hv,
            )

            # ── Generate & send HTML report ───────────────────────────────────
            html = generate_html_report(results, baseline_total=len(baseline))
            send_email_report(html, results, baseline_total=len(baseline))

            # ── Update baseline immediately (next part sees these subs) ───────
            update_baseline(BASELINE_FILE, results["new_subs"], baseline)
            baseline = baseline | results["new_subs"]
            grand_total_new += n_new

        else:
            log.info("Part %02d: no new subdomains discovered.", part_num)

        # ── Cooldown (skip after the final part) ─────────────────────────────
        if idx < len(parts_to_run) - 1:
            next_part = parts_to_run[idx + 1]
            log.info(
                "⏸  Cooldown: %s before Part %02d …",
                _fmt_duration(COOLDOWN_BETWEEN_PARTS), next_part,
            )
            time.sleep(COOLDOWN_BETWEEN_PARTS)

    log.info("")
    log.info("=" * 65)
    log.info("All %d parts complete.  Grand total new subdomains: %d",
             len(parts_to_run), grand_total_new)
    log.info("Developer: Ahmed Wael  |  BugBounty-Recon")
    log.info("=" * 65)


if __name__ == "__main__":
    main()
