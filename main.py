#!/usr/bin/env python3
"""
Bug Bounty Reconnaissance Automation Tool
==========================================
Author  : Ahmed Wael
Purpose : Automated subdomain discovery via batch-based subfinder execution,
          diffing against a persistent baseline, and immediate email alerting
          on newly observed subdomains.
License : MIT
"""

import os
import sys
import math
import logging
import smtplib
import subprocess
import tempfile
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants & Paths
# ---------------------------------------------------------------------------
WILDCARDS_URL = (
    "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/"
    "main/data/wildcards.txt"
)
BASELINE_FILE = Path("baseline_subs.txt")
TOTAL_BATCHES = 3


# ---------------------------------------------------------------------------
# Step 1 – Fetch wildcards from upstream source
# ---------------------------------------------------------------------------
def fetch_wildcards(url: str) -> list[str]:
    """Download the live wildcards list and return non-empty, stripped lines."""
    log.info("Fetching wildcards from: %s", url)
    try:
        response = requests.get(url, timeout=60)
        response.raise_for_status()
    except requests.RequestException as exc:
        log.error("Failed to fetch wildcards: %s", exc)
        sys.exit(1)

    lines = [line.strip() for line in response.text.splitlines() if line.strip()]
    log.info("Total wildcards fetched: %d", len(lines))
    return lines


# ---------------------------------------------------------------------------
# Step 2 – Dynamic batching
# ---------------------------------------------------------------------------
def get_batch(wildcards: list[str], batch_id: int, total_batches: int) -> list[str]:
    """
    Divide the wildcard list into *total_batches* equal slices and return the
    slice that corresponds to *batch_id* (1-indexed).
    """
    if not 1 <= batch_id <= total_batches:
        log.error(
            "BATCH_ID must be between 1 and %d (received %d).",
            total_batches,
            batch_id,
        )
        sys.exit(1)

    batch_size = math.ceil(len(wildcards) / total_batches)
    start = (batch_id - 1) * batch_size
    end = start + batch_size
    batch = wildcards[start:end]

    log.info(
        "Batch %d / %d selected: %d targets (index %d–%d).",
        batch_id,
        total_batches,
        len(batch),
        start,
        end - 1,
    )
    return batch


# ---------------------------------------------------------------------------
# Step 3 – Run subfinder
# ---------------------------------------------------------------------------
def run_subfinder(targets: list[str]) -> set[str]:
    """
    Write targets to a temporary file and invoke subfinder in silent mode.
    Returns the complete set of discovered subdomains.
    """
    discovered: set[str] = set()

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="recon_targets_"
    ) as targets_file:
        targets_file.write("\n".join(targets))
        targets_path = targets_file.name

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="recon_output_"
    ) as output_file:
        output_path = output_file.name

    log.info(
        "Running subfinder on %d targets. Output: %s", len(targets), output_path
    )

    try:
        result = subprocess.run(
            [
                "subfinder",
                "-dL", targets_path,   # domain list
                "-o",  output_path,    # output file
                "-silent",             # suppress banner/status lines
                "-all",                # use all sources
            ],
            capture_output=True,
            text=True,
            timeout=3600,              # 1-hour hard ceiling per batch
        )

        if result.returncode != 0:
            log.warning("subfinder exited with code %d.", result.returncode)
            log.warning("stderr: %s", result.stderr[:500])
        else:
            log.info("subfinder finished successfully.")

        output_text = Path(output_path).read_text()
        discovered = {
            line.strip().lower()
            for line in output_text.splitlines()
            if line.strip()
        }
        log.info("subfinder discovered %d subdomains.", len(discovered))

    except FileNotFoundError:
        log.error(
            "subfinder binary not found. Ensure it is installed and on PATH."
        )
        sys.exit(1)
    except subprocess.TimeoutExpired:
        log.error("subfinder timed out after 3600 seconds.")
        sys.exit(1)
    finally:
        # Clean up temporary files
        Path(targets_path).unlink(missing_ok=True)
        Path(output_path).unlink(missing_ok=True)

    return discovered


# ---------------------------------------------------------------------------
# Step 4 – Load baseline
# ---------------------------------------------------------------------------
def load_baseline(baseline_path: Path) -> set[str]:
    """Read the persistent baseline file into a set. Returns empty set if missing."""
    if not baseline_path.exists():
        log.info("No baseline file found at '%s'. Starting fresh.", baseline_path)
        return set()

    entries = {
        line.strip().lower()
        for line in baseline_path.read_text().splitlines()
        if line.strip()
    }
    log.info("Baseline loaded: %d known subdomains.", len(entries))
    return entries


# ---------------------------------------------------------------------------
# Step 5 – Diff: discover new subdomains
# ---------------------------------------------------------------------------
def diff_subdomains(
    current_subs: set[str], baseline_subs: set[str]
) -> set[str]:
    """Return subdomains present in current_subs but absent from baseline_subs."""
    new_subs = current_subs - baseline_subs
    log.info(
        "Diff result: %d current | %d baseline | %d NEW",
        len(current_subs),
        len(baseline_subs),
        len(new_subs),
    )
    return new_subs


# ---------------------------------------------------------------------------
# Step 6 – Send email alert
# ---------------------------------------------------------------------------
def send_email_alert(new_subs: set[str], batch_id: int) -> None:
    """
    Dispatch an SMTP email containing the list of newly discovered subdomains.

    Required environment variables:
        SMTP_EMAIL       – Sender email address (also used as SMTP login)
        SMTP_PASSWORD    – SMTP account password / app-specific password
        RECIPIENT_EMAIL  – Target inbox for alerts
        SMTP_HOST        – (optional) SMTP server host [default: smtp.gmail.com]
        SMTP_PORT        – (optional) SMTP server port [default: 587]
    """
    smtp_email = os.environ.get("SMTP_EMAIL", "").strip()
    smtp_password = os.environ.get("SMTP_PASSWORD", "").strip()
    recipient_email = os.environ.get("RECIPIENT_EMAIL", "").strip()
    smtp_host = os.environ.get("SMTP_HOST", "smtp.gmail.com").strip()
    smtp_port = int(os.environ.get("SMTP_PORT", "587"))

    if not all([smtp_email, smtp_password, recipient_email]):
        log.warning(
            "Email credentials incomplete. Skipping alert. "
            "Set SMTP_EMAIL, SMTP_PASSWORD, and RECIPIENT_EMAIL."
        )
        return

    subject = (
        f"[BugBounty-Recon] 🚨 {len(new_subs)} New Subdomain(s) Found "
        f"— Batch {batch_id}"
    )

    sorted_subs = sorted(new_subs)
    body_lines = [
        "New subdomains were discovered during your latest reconnaissance run.",
        f"Batch ID  : {batch_id}",
        f"New Count : {len(sorted_subs)}",
        "",
        "=" * 60,
        "NEW SUBDOMAINS:",
        "=" * 60,
        *sorted_subs,
        "",
        "=" * 60,
        "Stay ahead. Stay safe.",
        "— BugBounty-Recon | Ahmed Wael",
    ]
    body = "\n".join(body_lines)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_email
    msg["To"] = recipient_email
    msg.attach(MIMEText(body, "plain"))

    log.info("Sending email alert to %s via %s:%d …", recipient_email, smtp_host, smtp_port)
    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            server.starttls()
            server.login(smtp_email, smtp_password)
            server.sendmail(smtp_email, recipient_email, msg.as_string())
        log.info("Email alert sent successfully.")
    except smtplib.SMTPException as exc:
        log.error("Failed to send email alert: %s", exc)


# ---------------------------------------------------------------------------
# Step 7 – Update baseline
# ---------------------------------------------------------------------------
def update_baseline(baseline_path: Path, new_subs: set[str], baseline_subs: set[str]) -> None:
    """Merge new subdomains into the baseline file (sorted, deduplicated)."""
    merged = baseline_subs | new_subs
    baseline_path.write_text("\n".join(sorted(merged)) + "\n")
    log.info(
        "Baseline updated: %d total entries (+%d new).",
        len(merged),
        len(new_subs),
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
def main() -> None:
    """Orchestrate the full reconnaissance pipeline for a single batch."""

    # Resolve BATCH_ID from environment (GitHub Actions matrix injects this)
    batch_id_raw = os.environ.get("BATCH_ID", "").strip()
    if not batch_id_raw:
        log.error(
            "BATCH_ID environment variable is not set. "
            "Provide BATCH_ID=1, 2, or 3."
        )
        sys.exit(1)

    try:
        batch_id = int(batch_id_raw)
    except ValueError:
        log.error("BATCH_ID must be an integer (1, 2, or 3). Got: '%s'.", batch_id_raw)
        sys.exit(1)

    log.info("=" * 60)
    log.info("BugBounty-Recon  |  Author: Ahmed Wael")
    log.info("Starting Batch %d / %d", batch_id, TOTAL_BATCHES)
    log.info("=" * 60)

    # Pipeline
    wildcards      = fetch_wildcards(WILDCARDS_URL)
    batch_targets  = get_batch(wildcards, batch_id, TOTAL_BATCHES)
    current_subs   = run_subfinder(batch_targets)
    baseline_subs  = load_baseline(BASELINE_FILE)
    new_subs       = diff_subdomains(current_subs, baseline_subs)

    if new_subs:
        log.info("🚨 %d new subdomain(s) detected!", len(new_subs))
        for sub in sorted(new_subs):
            log.info("  + %s", sub)
        send_email_alert(new_subs, batch_id)
        update_baseline(BASELINE_FILE, new_subs, baseline_subs)
    else:
        log.info("✅ No new subdomains found in this batch run.")

    log.info("=" * 60)
    log.info("Batch %d complete.", batch_id)
    log.info("=" * 60)


if __name__ == "__main__":
    main()
