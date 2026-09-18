#!/usr/bin/env python3
"""
split_wildcards.py — Weekly Wildcard Fetcher & Splitter
=========================================================
Developer : Ahmed Wael
Purpose   : Fetch the live wildcard targets from the upstream bounty-targets-data
            repository and split the full list into 21 equal part files.
            Run once per week (every Monday) via GitHub Actions.
            The 21 part files are committed back to the repository so the daily
            recon workflow can process 3 parts per day across the week.
License   : MIT
"""

import logging
import math
import sys
from pathlib import Path

import requests

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
WILDCARDS_URL = (
    "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/"
    "main/data/wildcards.txt"
)
PARTS_DIR     = Path("parts")
TOTAL_PARTS   = 21       # 3 parts/day × 7 days = 21-part weekly rotation
REQUEST_TIMEOUT = 60     # seconds


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------
def fetch_wildcards(url: str) -> list[str]:
    """
    Download the live wildcards list from *url* and return a deduplicated,
    sorted list of non-empty, non-comment lines.

    Developer: Ahmed Wael
    """
    log.info("Fetching wildcard targets from: %s", url)
    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as exc:
        log.error("Failed to fetch wildcards list: %s", exc)
        sys.exit(1)

    lines: list[str] = []
    for raw in resp.text.splitlines():
        cleaned = raw.strip()
        # Skip blank lines and comment lines
        if not cleaned or cleaned.startswith("#"):
            continue
        # Normalise wildcard prefix (e.g. "*.example.com" → "example.com")
        if cleaned.startswith("*."):
            cleaned = cleaned[2:]
        lines.append(cleaned.lower())

    # Deduplicate while preserving deterministic order
    seen: set[str] = set()
    unique: list[str] = []
    for line in lines:
        if line not in seen:
            seen.add(line)
            unique.append(line)

    log.info("Total unique wildcard targets fetched: %d", len(unique))
    return unique


# ---------------------------------------------------------------------------
# Split & Write
# ---------------------------------------------------------------------------
def split_and_write(wildcards: list[str], parts_dir: Path, total_parts: int) -> None:
    """
    Divide *wildcards* into *total_parts* equal slices and write each slice
    to a numbered file inside *parts_dir*.

    File naming convention:  parts/part_01.txt … parts/part_21.txt

    Developer: Ahmed Wael
    """
    parts_dir.mkdir(parents=True, exist_ok=True)

    total = len(wildcards)
    batch_size = math.ceil(total / total_parts)

    log.info(
        "Splitting %d targets into %d parts (~%d targets per part).",
        total,
        total_parts,
        batch_size,
    )

    for part_num in range(1, total_parts + 1):
        start = (part_num - 1) * batch_size
        end   = min(start + batch_size, total)
        slice_ = wildcards[start:end]

        part_file = parts_dir / f"part_{part_num:02d}.txt"
        part_file.write_text("\n".join(slice_) + "\n", encoding="utf-8")

        log.info(
            "  Part %02d → %s  (%d targets, index %d–%d)",
            part_num,
            part_file,
            len(slice_),
            start,
            end - 1,
        )


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
def print_summary(parts_dir: Path, total_parts: int) -> None:
    """Log a concise summary of the split result."""
    log.info("=" * 60)
    log.info("Weekly split complete — Developer: Ahmed Wael")
    log.info("Parts directory : %s", parts_dir.resolve())
    log.info("Total part files: %d", total_parts)

    total_lines = 0
    for part_num in range(1, total_parts + 1):
        pf = parts_dir / f"part_{part_num:02d}.txt"
        if pf.exists():
            count = sum(1 for l in pf.read_text().splitlines() if l.strip())
            total_lines += count
    log.info("Total targets across all parts: %d", total_lines)
    log.info("=" * 60)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------
def main() -> None:
    log.info("=" * 60)
    log.info("BugBounty-Recon  |  split_wildcards.py")
    log.info("Developer: Ahmed Wael")
    log.info("=" * 60)

    wildcards = fetch_wildcards(WILDCARDS_URL)
    split_and_write(wildcards, PARTS_DIR, TOTAL_PARTS)
    print_summary(PARTS_DIR, TOTAL_PARTS)


if __name__ == "__main__":
    main()
