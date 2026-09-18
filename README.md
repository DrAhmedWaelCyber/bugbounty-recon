# BugBounty-Recon v3

<div align="center">

**Smart · Sustainable · Professional Bug Bounty Subdomain Reconnaissance**

[![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-Automated-2088FF?logo=github-actions&logoColor=white)](https://github.com/features/actions)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://python.org)
[![subfinder](https://img.shields.io/badge/subfinder-latest-00AAB5?logo=go&logoColor=white)](https://github.com/projectdiscovery/subfinder)
[![httpx](https://img.shields.io/badge/httpx-latest-00AAB5?logo=go&logoColor=white)](https://github.com/projectdiscovery/httpx)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Developer: Ahmed Wael**

</div>

---

## Overview

**BugBounty-Recon v3** is a high-performance, minimalist reconnaissance automation system built for serious bug bounty hunters. It continuously monitors the entire wildcard target universe from [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data), discovers brand-new subdomains faster than anyone else using differential baseline comparisons, probes active HTTP hosts, runs a 3-tier priority triage, and delivers a structured HTML email report after **each individual target file** — all automatically via GitHub Actions with zero timeout risk.

### Design Philosophy

| Constraint | Decision |
|---|---|
| No Web UI | Pure CLI + GitHub Actions automation |
| No database | Flat-file persistent baseline (`baseline_subs.txt`) |
| No vulnerability scanning | DNS discovery + HTTP probing only |
| No AI overhead | Deterministic, keyword-based priority triage |
| Zero timeout risk | 63-part split, 9 parts/day, sequential with 3-min cooldowns |
| Fastest discovery | Differential baseline — every new subdomain is surfaced immediately |

---

## What's New in v3

| Feature | v2 | v3 |
|---|---|---|
| Target part files | 21 | **63** |
| Parts per day | 3 | **9** |
| Execution model | All parts together | **Sequential, one at a time** |
| Cooldown between parts | None | **3-minute cooldown** |
| Email cadence | Once per daily run | **After every individual part** |
| Priority triage | Single-tier flag | **3-tier: CRITICAL / HIGH / MEDIUM** |
| HTML report | Single large block | **Modular section builders** |
| Timeout ceiling | 90 min | **360 min** (safe worst-case) |
| Live progress | Basic ticker | **ETA + percentage + rate per tool** |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  WEEKLY  (Monday 00:30 UTC)   split_wildcards.py            │
│                                                             │
│  Fetch wildcards.txt (live) ──► Deduplicate & normalise     │
│  Split into 63 equal parts  ──► parts/part_01.txt           │
│                                           ⋮                 │
│                                 parts/part_63.txt           │
│  git commit + push ──────────────────────────────────────►  │
└─────────────────────────────────────────────────────────────┘
         │
         │  parts/*.txt committed to repo
         ▼
┌─────────────────────────────────────────────────────────────┐
│  DAILY   (06:00 UTC every day)   main.py                    │
│                                                             │
│  Derive today's 9 parts from ISO day-of-week                │
│                                                             │
│  FOR each part (sequential):                                │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  1. load_part_targets()   read part_XX.txt          │    │
│  │  2. run_subfinder()       DNS discovery (live log)  │    │
│  │  3. run_httpx()           HTTP probe   (live log)   │    │
│  │  4. diff_subdomains()     new = current − baseline  │    │
│  │  5. triage_high_value()   CRITICAL / HIGH / MEDIUM  │    │
│  │  6. generate_html_report() modular branded report   │    │
│  │  7. send_email_report()   SMTP dispatch             │    │
│  │  8. update_baseline()     merge + write to disk     │    │
│  └─────────────────────────────────────────────────────┘    │
│           │                                                  │
│           ▼  (if not last part)                             │
│       ⏸  3-minute cooldown                                  │
│           │                                                  │
│           ▼  (next part)                                     │
│  git commit baseline_subs.txt + push                        │
└─────────────────────────────────────────────────────────────┘
```

---

## Repository Structure

```
bugbounty-recon/
├── split_wildcards.py              # Weekly: fetch + split into 63 parts
├── main.py                         # Daily: sequential multi-part pipeline
├── requirements.txt                # Python deps (requests only)
├── baseline_subs.txt               # Auto-managed persistent state
├── parts/                          # Auto-generated weekly (git-tracked)
│   ├── part_01.txt
│   ├── part_02.txt
│   ⋮
│   └── part_63.txt
├── .github/
│   └── workflows/
│       ├── weekly_split.yml        # Every Monday 00:30 UTC
│       └── daily_recon.yml         # Every day   06:00 UTC
└── README.md
```

---

## 63-Part Weekly Rotation Schedule

The 63 parts are consumed over 7 days at **9 parts per day**, processed sequentially:

| Day | UTC Cron | Parts | Cooldowns |
|---|---|---|---|
| Monday | 06:00 | 1 → 9 | 8 × 3 min |
| Tuesday | 06:00 | 10 → 18 | 8 × 3 min |
| Wednesday | 06:00 | 19 → 27 | 8 × 3 min |
| Thursday | 06:00 | 28 → 36 | 8 × 3 min |
| Friday | 06:00 | 37 → 45 | 8 × 3 min |
| Saturday | 06:00 | 46 → 54 | 8 × 3 min |
| Sunday | 06:00 | 55 → 63 | 8 × 3 min |

> **Full coverage every 7 days** with zero timeout risk. Each daily job has a safe 6-hour ceiling.

---

## Target Splitting: 21 → 63 Parts

The migration from 21 to 63 part files was a deliberate architectural decision for long-term sustainability:

```
Total wildcards : ~9,500 unique targets (fetched live every Monday)

21-part system  : ceil(9500 / 21) ≈ 453 targets/part  →  3 parts/day
63-part system  : ceil(9500 / 63) ≈ 151 targets/part  →  9 parts/day
```

### Why 63?

| Concern | 21 parts | 63 parts |
|---|---|---|
| Targets per part | ~453 | **~151** (3× smaller) |
| subfinder runtime per part | ~20–40 min | **~7–15 min** |
| httpx probe runtime per part | ~25–45 min | **~8–18 min** |
| Timeout exposure | Medium | **Near-zero** |
| Daily GitHub Actions ceiling | 90 min | **360 min** (9 sequential parts) |
| Coverage cycle | 7 days | **7 days** (maintained) |

Smaller parts mean each individual subfinder + httpx run fits well within GitHub Actions limits, and sequential execution with cooldowns prevents upstream API rate-limiting.

---

## Sequential Execution & 3-Minute Cooldown

Parts within a single daily run are processed **strictly sequentially** — never in parallel:

```
06:00  ▶ Part 01  [subfinder → httpx → diff → triage → email → baseline update]
         ⏸ 3-minute cooldown
       ▶ Part 02  [same pipeline, updated baseline]
         ⏸ 3-minute cooldown
       ▶ Part 03  ...
         ⏸  ...
       ▶ Part 09  [no cooldown after last part]
       ✅ git commit baseline_subs.txt → exit
```

**Why cooldowns matter:**
- Prevents upstream passive DNS sources from rate-limiting the subfinder API calls
- Allows httpx target servers time to reset connection state
- Gives the GitHub Actions runner memory a moment to garbage-collect between runs
- Ensures clean, readable logs with clear part-level separators

The baseline is updated **in-memory after each part**, so Part 02 never re-discovers subdomains that Part 01 already found and reported. Each email report is dispatched immediately after its part completes — you receive alerts in near-real-time throughout the day.

---

## Live Output Streaming & Progress Tracking

All subprocess calls (subfinder, httpx) use `subprocess.Popen` with line-by-line streaming, flushing after every line. GitHub Actions logs never freeze:

```
  [subfinder] api.example.com
  [subfinder] admin.target.io
  [subfinder] ⏳ Tick #1 | Elapsed: 30s | Found: 87 subdomains (from 151 targets) | Rate: 174.0/min | Timeout in: 59m 30s

  [httpx] {"url":"https://admin.target.io","status-code":200,"title":"Admin Panel",...}
  [httpx] ⏳ Tick #2 | Elapsed: 1m 00s | Probed: 43/87 (49.4%) | Rate: 43.0 hosts/min | ETA: 1m 02s
```

| Tool | Progress Mode | What the ticker shows |
|---|---|---|
| subfinder | `discover` | Elapsed · Subdomains found · Discovery rate · Timeout headroom |
| httpx | `probe` | Elapsed · Probed X/Y (%) · Rate · **ETA** |

The denominator (total targets/subdomains) is detected **dynamically** from the loaded part file on every run — no hardcoding.

---

## 3-Tier Priority Triage System

After httpx confirms active hosts among the newly discovered subdomains, the triage engine scores every flagged host into three priority tiers:

### Priority Algorithm

```python
CRITICAL  =  CRITICAL_KEYWORD in hostname  AND  HTTP 200
HIGH      =  CRITICAL_KEYWORD in hostname (any status)  OR  HTTP 200
MEDIUM    =  any HIGH_VALUE_KEYWORD in hostname
```

### Priority Tiers

| Tier | Badge | Colour | Meaning |
|---|---|---|---|
| ⚠ CRITICAL | `⚠ CRITICAL` | 🔴 Red `#dc2626` | High-impact attack surface, serving live content |
| ↑ HIGH | `↑ HIGH` | 🟠 Orange `#ea580c` | Sensitive panel or gated behind auth/firewall |
| ▲ MEDIUM | `▲ MEDIUM` | 🟡 Amber `#f59e0b` | Interesting but lower immediate risk |

### Critical Keywords (trigger CRITICAL/HIGH)

`admin` · `administrator` · `phpmyadmin` · `adminer` · `cpanel` · `whm` · `webmin` · `plesk` · `jenkins` · `gitlab` · `grafana` · `kibana` · `confluence` · `jira` · `sonar`

### Extended High-Value Keywords (trigger MEDIUM+)

`dev` · `staging` · `test` · `qa` · `uat` · `api` · `graphql` · `login` · `auth` · `sso` · `oauth` · `backup` · `portal` · `dashboard` · `console` · `panel` · `internal` · `intranet` · `vpn` · `prometheus` · `elastic` · `datadog` · `monitor` · `metrics` · `beta` · `mail` · `webmail` · `db` · `database` · `redis` · `cache` · `deploy` · `ci` · `cd` · `legacy` · `archive` · and more

---

## HTML Email Report

A **professional, modular HTML email report** is dispatched after every individual part completes. The report is built from independent section-builder functions for maintainability.

### Report Structure

```
┌──────────────────────────────────────────────────────┐
│  🔍 BugBounty-Recon          Part 07 / 63           │
│  Daily Intelligence Report                          │
│  2026-09-18 06:00 UTC  ·  Developed by Ahmed Wael  │
└──────────────────────────────────────────────────────┘

  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │  🌐 247  │  │  ✅  89  │  │  🚨  12  │  │  📚 15K  │
  │   NEW    │  │  ACTIVE  │  │   HIGH   │  │  TOTAL   │
  │   SUBS   │  │   HTTP   │  │  VALUE   │  │  KNOWN   │
  └──────────┘  └──────────┘  └──────────┘  └──────────┘

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  🚨 HIGH-VALUE TARGETS — Manual Inspection Required  [12]
  ┌───────────┬────────────────────┬────────┬──────────────────┐
  │ Priority  │ Hostname           │ Status │ Keywords         │
  ├───────────┼────────────────────┼────────┼──────────────────┤
  │⚠ CRITICAL │ admin.example.com  │  200   │ admin, dashboard  │
  │↑ HIGH     │ jenkins.target.io  │  403   │ jenkins, ci       │
  │▲ MEDIUM   │ dev.program.com    │  200   │ dev, staging      │
  └───────────┴────────────────────┴────────┴──────────────────┘

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  ✅ NEW ACTIVE HTTP HOSTS                            [89]
  ┌────────────────────────┬────────┬──────────┬────────────────┐
  │ Hostname               │ Status │ Server   │ Title          │
  ├────────────────────────┼────────┼──────────┼────────────────┤
  │ api.example.com        │  200   │ nginx    │ API Gateway    │
  │ beta.target.io         │  301   │ Apache   │ —              │
  └────────────────────────┴────────┴──────────┴────────────────┘

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  🌐 NEW DNS DISCOVERIES (no HTTP response)          [158]
  [mail.example.com] [ftp.target.io] [vpn.program.com] …

  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  BugBounty-Recon · Part 07/63 · Developed by Ahmed Wael
```

### Section Builder Functions

| Function | Renders |
|---|---|
| `_build_report_header()` | Dark gradient header, part/total, timestamp, developer credit |
| `_build_stat_cards()` | 4 coloured metric cards with top-border accents |
| `_build_hv_section()` | Priority-ranked high-value table (hidden if none) |
| `_build_active_table()` | HTTP hosts table, alternating rows, capped at 250 |
| `_build_dns_section()` | Pill display, capped at 400 (hidden if none) |
| `_build_footer()` | Two-column footer with attribution + run metadata |

### Email Subject Format

```
🚨 [BugBounty-Recon] Part 07/63 — 247 New Subs | 89 Active | 12 High-Value
📋 [BugBounty-Recon] Part 08/63 — 54 New Subs | 12 Active | 0 High-Value
```

---

## Setup

### 1. Fork / Clone This Repository

```bash
git clone https://github.com/<YOUR_USERNAME>/bugbounty-recon.git
cd bugbounty-recon
```

### 2. Add GitHub Secrets

Go to **Settings → Secrets and Variables → Actions → New repository secret**:

| Secret | Required | Description |
|---|---|---|
| `SMTP_EMAIL` | ✅ | Sender Gmail address |
| `SMTP_PASSWORD` | ✅ | Gmail App Password *(not your regular password)* |
| `RECIPIENT_EMAIL` | ✅ | Inbox that receives the alert emails |
| `SMTP_HOST` | ❌ | SMTP server (default: `smtp.gmail.com`) |
| `SMTP_PORT` | ❌ | SMTP port (default: `587`) |

> **Gmail App Password:** Enable 2FA → `myaccount.google.com → Security → App passwords` → generate a dedicated password for this tool.

### 3. Enable GitHub Actions

Go to **Actions → Enable Workflows**. Both workflows activate on schedule automatically.

### 4. Bootstrap the Parts Directory

Trigger **"Weekly — Wildcard Split"** manually from the Actions tab. This immediately populates `parts/part_01.txt` through `parts/part_63.txt` without waiting for Monday.

---

## Running Locally

### Install Dependencies

```bash
# Python
pip install -r requirements.txt

# Go reconnaissance tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Run the Weekly Split

```bash
python split_wildcards.py
# Produces parts/part_01.txt … parts/part_63.txt
```

### Run a Sequential Daily Batch (9 parts)

```bash
export PARTS="1,2,3,4,5,6,7,8,9"
export SMTP_EMAIL="you@gmail.com"
export SMTP_PASSWORD="your-app-password"
export RECIPIENT_EMAIL="alerts@yourdomain.com"

python main.py
# Processes parts sequentially with 3-min cooldowns between each
# Sends one HTML email report per part that contains new findings
```

### Run a Single Part (Testing)

```bash
export PARTS="1"
python main.py
```

---

## Persistent State & Baseline

`baseline_subs.txt` is a sorted, deduplicated flat file of every subdomain ever observed by the tool. It serves as the **differential reference** — the core mechanism that enables early, first-mover discovery:

```
new_subdomains = current_subfinder_output − baseline_subs
```

### Key baseline behaviours

- Updated **in-memory after each part** within a single daily run, so consecutive parts never re-report the same findings as each other
- Written to disk after each part that produces new discoveries
- Committed back to the repository at the end of each daily run via `GITHUB_TOKEN`
- Every commit message includes `[skip ci]` to prevent infinite workflow loops
- Grows monotonically — subdomains are never removed (removal would cause false re-discovery)

---

## Security Notes

- All credentials are injected via **GitHub Secrets only** — never hardcoded anywhere in the codebase.
- `GITHUB_TOKEN` permissions are scoped to `contents: write` on this repository only.
- subfinder operates at the **DNS layer only** — no direct HTTP requests to target infrastructure.
- httpx probing uses `-rate-limit 150` and `-threads 50` to behave as a polite, low-noise client.
- No vulnerability payloads, no exploitation, no active scanning — reconnaissance only.
- Every automation commit includes `[skip ci]` to prevent cascading workflow triggers.

---

## Workflow Reference

| Workflow | File | Trigger | Job Timeout | What it does |
|---|---|---|---|---|
| Weekly Split | `weekly_split.yml` | Mon 00:30 UTC + manual | 15 min | Fetch wildcards → split to 63 parts → commit |
| Daily Recon | `daily_recon.yml` | Daily 06:00 UTC + manual | **360 min** | Run 9 parts sequentially → per-part emails → commit baseline |

### Manual Override (workflow_dispatch)

Both workflows support **manual triggering** from the Actions tab:

- **Weekly Split** — no inputs required; always re-fetches and overwrites parts.
- **Daily Recon** — optionally specify a custom `parts` input (e.g., `5,6,7`) to re-run specific parts outside the normal schedule.

---

## Frequently Asked Questions

**Q: Why 63 parts instead of 21?**  
A: 63 = 9 parts/day × 7 days. Smaller parts (~151 targets each) run much faster per iteration, eliminating timeout risk entirely while maintaining the same 7-day full coverage cycle.

**Q: Why process parts sequentially instead of in parallel?**  
A: Parallel execution would exhaust subfinder's passive DNS API quotas, risk GitHub Actions runner memory limits, and make it impossible to update the baseline incrementally — causing duplicate alerts. Sequential is safer, cleaner, and produces better logs.

**Q: What happens if a part file doesn't exist yet?**  
A: The daily workflow includes an emergency fallback — if fewer than 63 part files are detected at runtime, it automatically runs `split_wildcards.py` before proceeding.

**Q: Will I get spammed if no new subdomains are found?**  
A: No. The email is sent **only** when `len(new_subs) > 0`. Silent parts log a clean "no new discoveries" message and proceed to the next part.

**Q: How large can `baseline_subs.txt` grow?**  
A: The global wildcard universe is ~9,500 targets, and typical subdomain discovery yields tens to hundreds of thousands of entries long-term. Git handles flat text files of this size efficiently with no performance concerns.

---

## License

MIT — free to use, modify, and distribute with attribution.

---

<div align="center">

Built with ❤️ by **Ahmed Wael**

*Stay ahead. Stay safe. Happy Hunting. 🎯*

</div>
