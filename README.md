# Python Scraper Webhook

Collects CVEs and cybersecurity news on a daily schedule with deduplication, safe writes, rate controls, and run/session logging.

## Core Behavior

- `cve_scraper.py`
  - Pulls CVEs from CVEProject GitHub
  - Stores compact records in `data/cves.json`
  - Keeps max `MAX_CVES` (default 10)
  - Dedup key: `cveMetadata.cveId`
  - Sort order: `datePublished` -> `dateReserved` -> `dateUpdated` -> `_fetched_at`
  - CVE API budget per run: `GITHUB_MAX_API_CALLS_PER_RUN` (default 80)

- `news_scraper.py`
  - Pulls headlines from CyberDaily AU
  - Stores in `data/cybersecurity_news.json`
  - Keeps max `MAX_HEADLINES` (default 10)
  - Dedup key: canonicalized `title + URL`
  - Newest entries first by `fetched_at`

- `main.py`
  - Runs both scrapers once daily at configurable `RUN_DAILY_AT` (default `01:00`)
  - Runs once immediately on start
  - Creates one log file per scheduler process run in `logs/`
  - Rotates logs (keeps newest 30 by default)
  - Writes run metadata to `data/runtime_status.json`

## Reliability and Security Controls

- Atomic JSON writes for data/status files
- Lock files prevent overlapping writers:
  - `data/.scheduler.lock`
  - `data/.cves.lock`
  - `data/.news.lock`
- HTTP retries with backoff+jitter for transient errors (429/5xx/network)
- Host/content-size/type validation on fetched data
- Optional verbose logs: set `SCRAPER_VERBOSE=1`

## Quick Start (No Manual Venv)

### Windows (PowerShell)

```powershell
.\run.ps1 main
.\run.ps1 cve
.\run.ps1 news
.\run.ps1 check
```

### Windows (CMD)

```bat
run.bat main
run.bat cve
run.bat news
run.bat check
```

### Linux/macOS (bash)

```bash
./run.sh main
./run.sh cve
./run.sh news
./run.sh check
```

Runner behavior:
- Auto-creates `.venv` if missing
- Installs dependencies only when `requirements.txt` hash changes (`.venv/.requirements.sha256`)
- For `main`/`cve`, loads `GITHUB_TOKEN` from environment or prompts for one

## Data and Runtime Files

- `data/cves.json`
- `data/cybersecurity_news.json`
- `data/runtime_status.json`
  - `last_run_started_at`
  - `last_run_completed_at`
  - `last_run_result` (`success`/`partial`/`failure`)
  - `last_successful_run_at`
  - per-scraper summary stats
- `logs/scraper_run_YYYYMMDD_HHMMSS.log`

## Manual Run (Optional)

If dependencies are already installed:

```powershell
python main.py
```

## Validation

Compile check:

```powershell
python -m py_compile cve_scraper.py news_scraper.py deduplication.py main.py check_data.py runtime_lock.py
```
