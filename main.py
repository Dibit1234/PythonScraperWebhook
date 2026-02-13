"""
Main Scheduler
Runs both CVE and News scrapers on a daily schedule
"""

import schedule
import time
from datetime import datetime
import sys
import json
import os
from pathlib import Path

# Import scrapers
from cve_scraper import run_cve_scraper
from news_scraper import run_news_scraper
from deduplication import remove_duplicate_entries_from_file, get_duplicate_count
from runtime_lock import FileLock

LOG_RETENTION_COUNT = 30
SCHEDULER_LOCK_PATH = "data/.scheduler.lock"
RUNTIME_STATUS_FILE = "data/runtime_status.json"
RUN_DAILY_AT = "01:00"


class TeeStream:
    """Write output to both console and log file."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for stream in self.streams:
            stream.write(data)
            stream.flush()

    def flush(self):
        for stream in self.streams:
            stream.flush()


def _atomic_write_json(path, data):
    path_obj = Path(path)
    path_obj.parent.mkdir(exist_ok=True)
    tmp_path = path_obj.with_suffix(path_obj.suffix + ".tmp")
    with open(tmp_path, "w", encoding="utf-8") as tmp_file:
        json.dump(data, tmp_file, indent=2, ensure_ascii=False)
    os.replace(tmp_path, path_obj)


def _read_runtime_status():
    if not os.path.exists(RUNTIME_STATUS_FILE):
        return {}
    try:
        with open(RUNTIME_STATUS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _update_runtime_status(changes):
    status = _read_runtime_status()
    status.update(changes)
    _atomic_write_json(RUNTIME_STATUS_FILE, status)


def rotate_old_logs():
    Path("logs").mkdir(exist_ok=True)
    log_files = sorted(
        Path("logs").glob("scraper_run_*.log"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for old_file in log_files[LOG_RETENTION_COUNT:]:
        try:
            old_file.unlink()
        except OSError:
            pass


def initialize_run_logging():
    """Create one log file per scheduler process run."""
    rotate_old_logs()
    Path("logs").mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = Path("logs") / f"scraper_run_{timestamp}.log"
    log_file = open(log_path, "a", encoding="utf-8")
    sys.stdout = TeeStream(sys.__stdout__, log_file)
    sys.stderr = TeeStream(sys.__stderr__, log_file)
    print(f"[Main] Logging to {log_path}")
    return log_file


def run_all_scrapers():
    """Run both scrapers"""
    run_started_at = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    _update_runtime_status({"last_run_started_at": run_started_at})

    print(f"\n{'='*60}")
    print(f"Running scrapers at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")
    cve_stats = {"fetched": 0, "saved_new": 0, "total_after": 0, "dropped_invalid": 0, "deduped": 0, "ok": False}
    news_stats = {"fetched": 0, "saved_new": 0, "total_after": 0, "dropped_invalid": 0, "deduped": 0, "ok": False}

    try:
        print("[Main] Starting CVE scraper...")
        cve_stats = run_cve_scraper()
        print("[Main] CVE scraper completed.")

        # Check for duplicates in CVE file
        cve_duplicates = get_duplicate_count("data/cves.json", 'cves')
        if cve_duplicates > 0:
            print(f"[Main] Found {cve_duplicates} duplicate CVEs, cleaning...")
            remove_duplicate_entries_from_file("data/cves.json", 'cves')
            cve_stats["deduped"] = cve_stats.get("deduped", 0) + cve_duplicates
        print(
            f"[Main][CVE Summary] fetched={cve_stats.get('fetched', 0)} "
            f"saved_new={cve_stats.get('saved_new', 0)} total_after={cve_stats.get('total_after', 0)} "
            f"dropped_invalid={cve_stats.get('dropped_invalid', 0)} deduped={cve_stats.get('deduped', 0)}"
        )
        print()
    except Exception as e:
        print(f"[Main] Error in CVE scraper: {str(e)}\n")

    try:
        print("[Main] Starting News scraper...")
        news_stats = run_news_scraper()
        print("[Main] News scraper completed.")

        # Check for duplicates in news file
        news_duplicates = get_duplicate_count("data/cybersecurity_news.json", 'headlines')
        if news_duplicates > 0:
            print(f"[Main] Found {news_duplicates} duplicate headlines, cleaning...")
            remove_duplicate_entries_from_file("data/cybersecurity_news.json", 'headlines')
            news_stats["deduped"] = news_stats.get("deduped", 0) + news_duplicates
        print(
            f"[Main][News Summary] fetched={news_stats.get('fetched', 0)} "
            f"saved_new={news_stats.get('saved_new', 0)} total_after={news_stats.get('total_after', 0)} "
            f"dropped_invalid={news_stats.get('dropped_invalid', 0)} deduped={news_stats.get('deduped', 0)}"
        )
        print()
    except Exception as e:
        print(f"[Main] Error in News scraper: {str(e)}\n")

    completed_at = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    if cve_stats.get("ok") and news_stats.get("ok"):
        run_result = "success"
    elif not cve_stats.get("ok") and not news_stats.get("ok"):
        run_result = "failure"
    else:
        run_result = "partial"
    status_update = {
        "last_run_completed_at": completed_at,
        "last_run_result": run_result,
        "cve": cve_stats,
        "news": news_stats,
    }
    if run_result == "success":
        status_update["last_successful_run_at"] = completed_at
    _update_runtime_status(status_update)

    print(f"{'='*60}")
    print(f"Scrapers completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Next run scheduled at {RUN_DAILY_AT}")
    print(f"{'='*60}\n")


def schedule_scrapers():
    """Schedule the scrapers to run once daily."""
    scheduler_lock = FileLock(SCHEDULER_LOCK_PATH, timeout_seconds=1, stale_seconds=3600)
    if not scheduler_lock.acquire():
        print("[Main] Another scheduler instance appears to be running. Exiting.")
        return

    log_file = initialize_run_logging()

    # Schedule one run daily at configured time (24h format HH:MM)
    schedule.every().day.at(RUN_DAILY_AT).do(run_all_scrapers)
    
    print(f"[Main] Scheduler initialized at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[Main] Scrapers will run once daily at {RUN_DAILY_AT}")
    print("[Main] Press Ctrl+C to stop\n")
    
    # Run initial scrape immediately
    run_all_scrapers()
    
    # Keep scheduler running
    try:
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute if a task should run
    except KeyboardInterrupt:
        print("\n[Main] Scheduler stopped by user")
        sys.exit(0)
    finally:
        log_file.close()
        scheduler_lock.release()


if __name__ == "__main__":
    schedule_scrapers()
