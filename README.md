# Python Scraper Webhook

Automated web scraper that collects CVEs and cybersecurity news headlines with periodic updates.

## Features

- **CVE Scraper**: Fetches the 10 most recent CVEs from [CVEProject GitHub](https://github.com/CVEProject/cvelistV5/tree/main/cves)
  - Saves to `data/cves.json`
  - **Maintains only 10 most recent CVEs** - automatically removes oldest when new ones arrive
  - **Prevents duplicates** - CVE IDs are tracked and checked before adding
  - Stores in order: newest to oldest
  - Updates every 15 minutes

- **News Scraper**: Crawls [CyberDaily AU](https://www.cyberdaily.au/) for latest cybersecurity headlines
  - Saves to `data/cybersecurity_news.json`
  - **Clean title extraction** - separates category from headline text
  - **Filters out subscribe entries** - automatically removes subscription prompts
  - **Prevents duplicates** - uses title + link combination as unique identifier
  - Maintains up to 500 recent headlines
  - Updates every 15 minutes

- **Deduplication Module**: Utility functions for managing duplicate entries
  - `deduplication.py` provides helper functions
  - Automatic duplicate detection and cleanup
  - Can be run manually to clean existing data files

- **Scheduler**: Runs both scrapers automatically every 15 minutes
  - Runs initial scrape immediately on start
  - Maintains separate JSON files for easy access
  - Built-in duplicate checking and cleanup

## Data Structure

### CVEs (data/cves.json)
```json
[
  {
    "cveMetadata": {
      "cveId": "CVE-2026-2011",
      "state": "PUBLISHED",
      "datePublished": "2026-02-13T...",
      ...
    },
    "containers": {...},
    "_fetched_at": "2026-02-13T10:28:43.123456"
  }
]
```
- **Max entries**: 10
- **Order**: Newest first
- **Unique key**: cveId

### Headlines (data/cybersecurity_news.json)
```json
[
  {
    "title": "Op-Ed: Latest Microsoft Patch Tuesday reveals 55 vulnerabilities",
    "category": "Security",
    "link": "https://www.cyberdaily.au/security/...",
    "description": "",
    "fetched_at": "2026-02-13T10:28:43.123456",
    "source": "CyberDaily AU"
  }
]
```
- **Max entries**: 500
- **Order**: Newest first
- **Unique key**: title + link combination

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Run the main scheduler (recommended)
```bash
python main.py
```
The scheduler will:
1. Run scrapers immediately on startup
2. Run again every 15 minutes automatically
3. Automatically deduplicate new entries
4. Keep only the most recent 10 CVEs
5. Keep up to 500 recent headlines
6. Press Ctrl+C to stop

### Run individual scrapers
```bash
python cve_scraper.py      # Fetch latest CVEs
python news_scraper.py     # Fetch latest headlines
```

### Check data status
```bash
python check_data.py       # View current data counts and sample entries
```

### Clean existing data manually
```python
from deduplication import remove_duplicate_entries_from_file

# Remove duplicates from CVE data
remove_duplicate_entries_from_file("data/cves.json", 'cves')

# Remove duplicates from news data
remove_duplicate_entries_from_file("data/cybersecurity_news.json", 'headlines')
```

## Output Files

- `data/cves.json` - Array of 10 most recent CVE objects from GitHub (newest first)
- `data/cybersecurity_news.json` - Array of recent headline objects from CyberDaily AU (newest first)

## Dependencies

- `requests` - HTTP requests for API calls
- `beautifulsoup4` - HTML parsing for web scraping
- `lxml` - XML/HTML parsing engine
- `schedule` - Job scheduling for periodic runs
- `python-dateutil` - Date and time utilities

## Key Features

✅ **Smart Deduplication**
- CVEs: Tracked by ID, automatically prevents re-adding
- Headlines: Tracked by title + link combination

✅ **Size Management**
- CVEs: Maintains sliding window of 10 most recent (removes oldest when new arrives)
- Headlines: Keeps up to 500 recent entries

✅ **Quality Control**
- News titles/categories properly separated
- Unwanted entries (e.g., "subscribe") filtered out
- Proper error handling and logging

✅ **Reliable Scheduling**
- Periodic updates every 15 minutes
- Continues running even if individual scrapes fail
- Detailed logging of all operations

## Notes

- The CVE scraper uses the GitHub API and fetches JSON files directly from the repository
- The news scraper parses HTML from CyberDaily AU's website
- Both scrapers include error handling and logging
- Data files are stored in human-readable JSON format
- All timestamps are in ISO 8601 format

## Future Enhancements

- Add database support for better data management
- Create REST API endpoints to query data
- Add email alerts for critical CVEs
- Implement webhook notifications
- Add filtering and search capabilities
- Export data to CSV or other formats
- Add data retention policies based on age

