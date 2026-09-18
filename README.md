# BugBounty-Recon v2

> **Smart, fully sustainable, and professional automated Bug Bounty subdomain reconnaissance pipeline.**
>
> **Developer:** Ahmed Wael  
> **License:** MIT

---

## Overview

**BugBounty-Recon v2** is a high-performance, minimalist reconnaissance automation system built for serious bug bounty hunters. It continuously monitors the entire wildcard target universe from [bounty-targets-data](https://github.com/arkadiyt/bounty-targets-data), discovers new subdomains, probes for active HTTP hosts, triages high-value targets, and delivers a **professional branded HTML email report** — all automatically via GitHub Actions.

### Design Philosophy

| Constraint | Decision |
|---|---|
| No Web UI | Pure CLI + GitHub Actions |
| No database | Flat-file persistent state (`baseline_subs.txt`) |
| No vulnerability scanning | DNS-level discovery + HTTP probing only |
| No AI overhead | Deterministic, keyword-based triage |
| Rate-limit safe | 21-part weekly rotation, 3 parts/day |
| Timeout safe | Sub-90-minute daily runs via part sizing |

---

## Architecture

```
                     ┌──────────────────────────────────┐
  WEEKLY (Monday)    │       split_wildcards.py          │
                     │  Fetch wildcards.txt → 21 parts   │
                     │  parts/part_01.txt … part_21.txt  │
                     └────────────┬─────────────────────┘
                                  │ git commit + push
                     ┌────────────▼─────────────────────┐
  DAILY (06:00 UTC)  │            main.py                │
                     │                                   │
                     │  Day-of-week → 3 parts/day        │
                     │  Mon→1,2,3  Tue→4,5,6  …          │
                     │                                   │
                     │  1. Load part targets             │
                     │  2. subfinder  (DNS discovery)    │
                     │  3. httpx      (HTTP probing)     │
                     │  4. Set diff   (new assets)       │
                     │  5. Triage     (high-value kw)    │
                     │  6. HTML report generation        │
                     │  7. SMTP email dispatch           │
                     │  8. Baseline update + git push    │
                     └──────────────────────────────────┘
```

---

## Repository Structure

```
bugbounty-recon/
├── split_wildcards.py              # Weekly: fetch + split into 21 parts
├── main.py                         # Daily: full recon pipeline
├── requirements.txt                # Python: requests only
├── baseline_subs.txt               # Auto-managed persistent state
├── parts/                          # Auto-generated weekly (git-tracked)
│   ├── part_01.txt
│   ├── part_02.txt
│   ⋮
│   └── part_21.txt
├── .github/
│   └── workflows/
│       ├── weekly_split.yml        # Runs every Monday 00:30 UTC
│       └── daily_recon.yml         # Runs every day 06:00 UTC
└── README.md
```

---

## Weekly Rotation Schedule

The 21 parts are consumed over 7 days at 3 parts per day:

| Day | UTC Cron | Parts Processed |
|---|---|---|
| Monday | 06:00 | 1, 2, 3 |
| Tuesday | 06:00 | 4, 5, 6 |
| Wednesday | 06:00 | 7, 8, 9 |
| Thursday | 06:00 | 10, 11, 12 |
| Friday | 06:00 | 13, 14, 15 |
| Saturday | 06:00 | 16, 17, 18 |
| Sunday | 06:00 | 19, 20, 21 |

---

## Email Report

Each successful daily run generates a **professional, responsive HTML email report** with:

- **Header** — Tool name, run timestamp, parts processed, "Developed by Ahmed Wael"
- **Stats Cards** — New Subdomains | Active HTTP Hosts | High-Value Alerts
- **Active Hosts Table** — hostname, HTTP status badge (colour-coded), page title, keyword tags
- **High-Value Targets Section** — Dedicated table for flagged hosts requiring manual inspection
- **DNS-Only Section** — Subdomains found via DNS but not yet reachable over HTTP
- **Footer** — Attribution, "Developed by Ahmed Wael", generation metadata

### High-Value Keywords

Hosts are flagged if their name contains any of these tokens:

`admin`, `dev`, `staging`, `test`, `qa`, `uat`, `api`, `graphql`, `login`, `auth`, `sso`, `backup`,
`portal`, `dashboard`, `console`, `panel`, `internal`, `intranet`, `vpn`, `jenkins`, `gitlab`,
`jira`, `confluence`, `grafana`, `kibana`, `phpmyadmin`, `adminer`, `cpanel`, `monitor`,
`metrics`, `beta`, `mail`, `webmail`, `db`, `database`, `redis`, `cache`, `old`, `legacy`, and more.

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
| `SMTP_PASSWORD` | ✅ | Gmail App Password (not your regular password) |
| `RECIPIENT_EMAIL` | ✅ | Inbox that receives the alert emails |
| `SMTP_HOST` | ❌ | SMTP host (default: `smtp.gmail.com`) |
| `SMTP_PORT` | ❌ | SMTP port (default: `587`) |

> **Gmail App Password:** Enable 2FA → `myaccount.google.com → Security → App passwords` → generate one for this tool.

### 3. Enable GitHub Actions

Go to **Actions → Enable Workflows**. Both workflows will run automatically on schedule.

### 4. Run the Initial Split (Optional)

Trigger `Weekly — Wildcard Split` manually from the Actions tab to populate the `parts/` directory immediately without waiting for Monday.

---

## Running Locally

### Install Dependencies

```bash
# Python
pip install -r requirements.txt

# Go tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Run the Weekly Split

```bash
python split_wildcards.py
```

### Run a Daily Recon Batch

```bash
export PARTS="1,2,3"
export SMTP_EMAIL="you@gmail.com"
export SMTP_PASSWORD="your-app-password"
export RECIPIENT_EMAIL="alerts@yourdomain.com"

python main.py
```

---

## How Splitting Works

```
Total wildcards: ~9,500 unique targets (dynamic, fetched live)

Batch size = ceil(9500 / 21) ≈ 453 targets per part

part_01.txt  → targets[0    : 453]
part_02.txt  → targets[453  : 906]
…
part_21.txt  → targets[8568 : 9500]
```

The count is recalculated fresh every Monday, so the system auto-adjusts as the upstream list grows.

---

## Persistent State

`baseline_subs.txt` is a sorted, deduplicated flat file of every subdomain ever seen. After each run, the workflow commits and pushes any new entries — so state persists across all future runs with zero external storage or database.

---

## Security Notes

- All credentials are **GitHub Secrets only** — never hardcoded anywhere in the codebase.
- `baseline_subs.txt` is committed using the built-in `GITHUB_TOKEN` scoped to this repository only.
- subfinder performs DNS-level discovery only — no HTTP requests, no live host interaction.
- httpx probing uses reasonable rate-limiting (`-rate-limit 150`) to avoid triggering WAFs.
- Every commit from automation includes `[skip ci]` to prevent infinite workflow loops.

---

## Workflow Summary

| Workflow | File | Trigger | Duration |
|---|---|---|---|
| Weekly Split | `weekly_split.yml` | Mon 00:30 UTC | ~2 min |
| Daily Recon | `daily_recon.yml` | Daily 06:00 UTC | ~60–80 min |

---

## License

MIT — free to use, modify, and distribute with attribution.

---

*Built with ❤️ by **Ahmed Wael***
