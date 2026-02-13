# Python Scraper Webhook

Collects CVEs and cybersecurity news on a 15-minute schedule.

## What It Does

- `cve_scraper.py`
  - Pulls CVEs from CVEProject GitHub
  - Saves to `data/cves.json`
  - Keeps max 10 records (controlled by `MAX_CVES` at top of file)
  - Dedup key: `cveMetadata.cveId`
  - Sort order: newest by `datePublished` (fallback: `dateReserved`, `dateUpdated`, `_fetched_at`)
  - Startup log shows auth state (`token detected` / `no token`) and per-run API budget
  - Per-run GitHub API budget: `GITHUB_MAX_API_CALLS_PER_RUN = 80`
  - Safety note: with 15-minute schedule, this stays under 500 requests/hour even with startup run timing

- `news_scraper.py`
  - Pulls headlines from CyberDaily AU
  - Saves to `data/cybersecurity_news.json`
  - Keeps max 10 records (controlled by `MAX_HEADLINES` at top of file)
  - Dedup key: canonicalized `title + URL`

- `main.py`
  - Runs both scrapers every 15 minutes
  - Runs once immediately on start
  - Performs duplicate cleanup checks

## Recommended Run (No Manual Venv)

Use the runner scripts. They auto-create `.venv` (if missing) and install dependencies.
For `main`/`cve` modes, the runner also:
- loads `GITHUB_TOKEN` from user environment if available
- prompts for a token if none is found

Windows (PowerShell):

```powershell
.\run.ps1 main
.\run.ps1 cve
.\run.ps1 news
.\run.ps1 check
```

Windows (CMD):

```bat
run.bat main
run.bat cve
run.bat news
run.bat check
```

Linux/macOS (bash):

```bash
./run.sh main
./run.sh cve
./run.sh news
./run.sh check
```

## VS Code Tasks

- `Run Scrapers (15-minute schedule)`
- `Run CVE Scraper Only`
- `Run News Scraper Only`

These tasks call `run.ps1` directly.

## Manual Run (Optional)

If dependencies are already installed:

```powershell
python main.py
```

## Data Files

- `data/cves.json`: max 10, deduped by CVE ID, newest first
- `data/cybersecurity_news.json`: max 10, deduped by canonical title+URL, newest first
