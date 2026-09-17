# BugBounty-Recon

> **Lightweight, high-performance, minimalist automation tool for Bug Bounty subdomain reconnaissance.**
>
> **Author:** Ahmed Wael  
> **License:** MIT

---

## Overview

**BugBounty-Recon** continuously monitors wildcard bug bounty targets for newly observed subdomains by running scheduled reconnaissance via GitHub Actions. When new assets are discovered, you receive an immediate email alert.

### Design Philosophy

- **No Web UI** — pure CLI / GitHub Actions automation
- **No database** — flat-file persistent state (`baseline_subs.txt`)
- **No vulnerability scanning** — pure subdomain discovery only
- **No HTTP probing** — no false-positive noise from live-host filtering
- **No AI overhead** — deterministic, fast, predictable

---

## Architecture

```
wildcards.txt (live fetch)
        │
        ▼
  Dynamic Batching  (Batch 1 / 2 / 3)
        │
        ▼
  subfinder  (fast/silent, all sources)
        │
        ▼
  Set Diff  ──────────── baseline_subs.txt
        │
    new_subs?
       ├── YES ──► Email Alert  +  Baseline Update  +  Git Push
       └── NO  ──► Exit cleanly
```

---

## Key Features

| Feature | Detail |
|---|---|
| Live wildcard fetch | Pulls from `bounty-targets-data` on every run |
| Dynamic batching | Splits total list into 3 equal batches automatically |
| Batch rotation | GitHub Actions matrix runs each batch at different scheduled times |
| Diffing engine | Python set arithmetic — zero dependencies beyond `requests` |
| Email alerts | SMTP via `smtplib` (standard library), TLS secured |
| Persistent state | `baseline_subs.txt` committed back to the repo after each run |

---

## Repository Structure

```
bugbounty-recon/
├── main.py                         # Core reconnaissance pipeline
├── requirements.txt                # Python dependencies
├── baseline_subs.txt               # Auto-managed persistent state (git-tracked)
├── .github/
│   └── workflows/
│       └── recon.yml               # GitHub Actions CI/CD workflow
└── README.md                       # This file
```

---

## Setup

### 1. Fork / Clone this Repository

```bash
git clone https://github.com/<YOUR_USERNAME>/bugbounty-recon.git
cd bugbounty-recon
```

### 2. Install Dependencies Locally (optional)

```bash
pip install -r requirements.txt
```

### 3. Install subfinder

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### 4. Configure GitHub Secrets

Go to **Settings → Secrets and Variables → Actions → New repository secret** and add:

| Secret Name | Description |
|---|---|
| `SMTP_EMAIL` | Sender Gmail address (e.g. `yourname@gmail.com`) |
| `SMTP_PASSWORD` | Gmail App Password *(not your regular password — see below)* |
| `RECIPIENT_EMAIL` | Inbox that receives the alerts |

> **Gmail App Password:** Enable 2FA on your Google account, then go to  
> `myaccount.google.com → Security → 2-Step Verification → App passwords`  
> and generate a dedicated password for this tool.

You may also optionally set:

| Secret Name | Default | Description |
|---|---|---|
| `SMTP_HOST` | `smtp.gmail.com` | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP server port (STARTTLS) |

### 5. Initialize the Baseline (First Run)

On the very first run, `baseline_subs.txt` will not exist. The script handles this gracefully — every subdomain found becomes a "new" discovery and the file is created automatically. Subsequent runs will diff against this foundation.

---

## Running Locally

```bash
export BATCH_ID=1
export SMTP_EMAIL="you@gmail.com"
export SMTP_PASSWORD="your-app-password"
export RECIPIENT_EMAIL="alerts@yourdomain.com"

python main.py
```

Set `BATCH_ID` to `1`, `2`, or `3` to process each third of the wildcard list.

---

## GitHub Actions Schedule

The workflow (`.github/workflows/recon.yml`) fires **3 times per day** at:

| UTC Time | Batch | ~Local (UTC+3) |
|---|---|---|
| `00:00` | Batch 1 | 03:00 |
| `08:00` | Batch 2 | 11:00 |
| `16:00` | Batch 3 | 19:00 |

Each run processes one third of the wildcard list, ensuring full target coverage every 24 hours with minimal resource consumption per job.

---

## Email Alert Format

```
Subject: [BugBounty-Recon] 🚨 42 New Subdomain(s) Found — Batch 2

New subdomains were discovered during your latest reconnaissance run.
Batch ID  : 2
New Count : 42

============================================================
NEW SUBDOMAINS:
============================================================
admin.example.com
api-v2.target.io
dev.another-program.com
...
============================================================
Stay ahead. Stay safe.
— BugBounty-Recon | Ahmed Wael
```

---

## How Batching Works

```
Total wildcards: 9,000 targets
Batch size     : ceil(9000 / 3) = 3,000

Batch 1  →  targets[0    : 3000]
Batch 2  →  targets[3000 : 6000]
Batch 3  →  targets[6000 : 9000]
```

The wildcard count is fetched dynamically each run, so the batch size auto-adjusts as the upstream list grows.

---

## Persistent State

`baseline_subs.txt` is a sorted, deduplicated flat file of all previously seen subdomains. After each run, the GitHub Actions workflow commits and pushes any updates back to the repository — so state persists across all future runs with zero external storage.

---

## Security Notes

- All credentials are injected exclusively via **GitHub Secrets** (never hardcoded).
- The `baseline_subs.txt` file is committed using the built-in `GITHUB_TOKEN` with write permissions scoped to the repository only.
- subfinder is invoked without any HTTP probing flags — it performs DNS-level discovery only.

---

## License

MIT — free to use, modify, and distribute with attribution.

---

*Built with ❤️ by **Ahmed Wael***
