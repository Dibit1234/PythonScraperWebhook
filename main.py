"""
Main Scheduler
Runs both CVE and News scrapers on a 15-minute schedule
"""

import schedule
import time
from datetime import datetime
import sys
from pathlib import Path

# Import scrapers
from cve_scraper import run_cve_scraper
from news_scraper import run_news_scraper
from deduplication import remove_duplicate_entries_from_file, get_duplicate_count


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


def initialize_run_logging():
    """Create one log file per scheduler process run."""
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
    print(f"\n{'='*60}")
    print(f"Running scrapers at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")
    
    try:
        print("[Main] Starting CVE scraper...")
        run_cve_scraper()
        print("[Main] CVE scraper completed.")
        
        # Check for duplicates in CVE file
        cve_duplicates = get_duplicate_count("data/cves.json", 'cves')
        if cve_duplicates > 0:
            print(f"[Main] Found {cve_duplicates} duplicate CVEs, cleaning...")
            remove_duplicate_entries_from_file("data/cves.json", 'cves')
        print()
    except Exception as e:
        print(f"[Main] Error in CVE scraper: {str(e)}\n")
    
    try:
        print("[Main] Starting News scraper...")
        run_news_scraper()
        print("[Main] News scraper completed.")
        
        # Check for duplicates in news file
        news_duplicates = get_duplicate_count("data/cybersecurity_news.json", 'headlines')
        if news_duplicates > 0:
            print(f"[Main] Found {news_duplicates} duplicate headlines, cleaning...")
            remove_duplicate_entries_from_file("data/cybersecurity_news.json", 'headlines')
        print()
    except Exception as e:
        print(f"[Main] Error in News scraper: {str(e)}\n")
    
    print(f"{'='*60}")
    print(f"Scrapers completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Next run scheduled in 15 minutes")
    print(f"{'='*60}\n")


def schedule_scrapers():
    """Schedule the scrapers to run every 15 minutes"""
    log_file = initialize_run_logging()

    # Schedule the job every 15 minutes
    schedule.every(15).minutes.do(run_all_scrapers)
    
    print(f"[Main] Scheduler initialized at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("[Main] Scrapers will run every 15 minutes")
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


if __name__ == "__main__":
    schedule_scrapers()
