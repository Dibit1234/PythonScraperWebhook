"""Scrape cybersecurity headlines from CyberDaily."""

import json
import os
import re
import tempfile
import random
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from deduplication import headline_dedup_key
from runtime_lock import FileLock

NEWS_FILE = "data/cybersecurity_news.json"
CYBERDAILY_URL = "https://www.cyberdaily.au/"
ALLOWED_NEWS_HOSTS = {"www.cyberdaily.au", "cyberdaily.au"}
MAX_HTML_BYTES = 5_000_000
MAX_HEADLINES = 10
MAX_TITLE_LENGTH = 300
MAX_LINK_LENGTH = 500
MAX_DESCRIPTION_LENGTH = 1000
HTTP_MAX_RETRIES = 3
HTTP_BACKOFF_BASE_SECONDS = 0.5
HTTP_BACKOFF_JITTER_MAX_SECONDS = 0.3
FILE_LOCK_TIMEOUT_SECONDS = 3
FILE_LOCK_STALE_SECONDS = 600
VERBOSE = os.getenv("SCRAPER_VERBOSE", "0") == "1"

_SESSION = requests.Session()


def _log(message):
    print(message)


def _vlog(message):
    if VERBOSE:
        print(message)


def _is_allowed_url(url, allowed_hosts):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    host = (parsed.hostname or "").lower()
    return host in allowed_hosts


def _sanitize_text(text):
    if not text:
        return ""
    cleaned = " ".join(text.split())
    return cleaned[:MAX_DESCRIPTION_LENGTH]


def _normalize_link(link):
    if not link:
        return ""
    absolute = urljoin(CYBERDAILY_URL, link)
    parsed = urlparse(absolute)
    if parsed.scheme not in {"http", "https"}:
        return ""
    if (parsed.hostname or "").lower() not in ALLOWED_NEWS_HOSTS:
        return ""
    return absolute[:MAX_LINK_LENGTH]


def _parse_iso_datetime(value):
    if not value or not isinstance(value, str):
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def _to_utc_z(value):
    parsed = _parse_iso_datetime(value)
    if not parsed:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _atomic_write_json(path, data):
    parent = Path(path).parent
    parent.mkdir(exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_", suffix=".json", dir=str(parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
            json.dump(data, tmp_file, indent=2, ensure_ascii=False)
        os.replace(tmp_path, path)
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


def _is_valid_headline_record(headline):
    if not isinstance(headline, dict):
        return False
    title = headline.get("title")
    if not isinstance(title, str) or not title.strip():
        return False
    link = headline.get("link", "")
    if not isinstance(link, str):
        return False
    fetched_at = headline.get("fetched_at", "")
    if not isinstance(fetched_at, str) or not _parse_iso_datetime(fetched_at):
        return False
    return True


def _fetch_news_page():
    if not _is_allowed_url(CYBERDAILY_URL, ALLOWED_NEWS_HOSTS):
        raise ValueError(f"Blocked URL: {CYBERDAILY_URL}")

    headers = {"User-Agent": "PythonScraperWebhook/1.0"}
    response = None
    for attempt in range(HTTP_MAX_RETRIES):
        try:
            response = _SESSION.get(CYBERDAILY_URL, headers=headers, timeout=15)
        except requests.exceptions.RequestException:
            if attempt == HTTP_MAX_RETRIES - 1:
                raise
            backoff = HTTP_BACKOFF_BASE_SECONDS * (2 ** attempt) + random.uniform(0, HTTP_BACKOFF_JITTER_MAX_SECONDS)
            time.sleep(backoff)
            continue

        if response.status_code == 429 or response.status_code >= 500:
            if attempt == HTTP_MAX_RETRIES - 1:
                response.raise_for_status()
            backoff = HTTP_BACKOFF_BASE_SECONDS * (2 ** attempt) + random.uniform(0, HTTP_BACKOFF_JITTER_MAX_SECONDS)
            time.sleep(backoff)
            continue

        response.raise_for_status()
        break

    if response is None:
        raise RuntimeError("Failed to fetch news page")

    final_url = response.url or CYBERDAILY_URL
    if not _is_allowed_url(final_url, ALLOWED_NEWS_HOSTS):
        raise ValueError(f"Blocked redirect: {final_url}")

    content_type = (response.headers.get("Content-Type") or "").lower()
    if "html" not in content_type:
        raise ValueError(f"Unexpected content type: {content_type}")

    if len(response.content) > MAX_HTML_BYTES:
        raise ValueError("Payload too large")

    return BeautifulSoup(response.content, "html.parser")


def _extract_headline_data(container):
    title_elem = container.find(["h1", "h2", "h3", "a"])
    if not title_elem:
        return None

    title = _sanitize_text(title_elem.get_text(" ", strip=True))
    if not title or "subscribe" in title.lower():
        return None

    link_elem = container.find("a", href=True)
    link = _normalize_link(link_elem["href"]) if link_elem else ""

    desc_elem = container.find(["p", "span", "div"], class_=re.compile("excerpt|summary|description", re.I))
    description = _sanitize_text(desc_elem.get_text(" ", strip=True)) if desc_elem else ""

    return {
        "title": title[:MAX_TITLE_LENGTH],
        "category": "General",
        "link": link,
        "description": description[:MAX_DESCRIPTION_LENGTH],
        "fetched_at": _to_utc_z(datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")),
        "source": "CyberDaily AU",
    }


def scrape_cyberdaily_headlines():
    """Fetch current headlines from CyberDaily."""
    try:
        _log("[News Scraper] Fetching headlines from CyberDaily AU...")
        soup = _fetch_news_page()

        containers = soup.find_all(["article", "div"], class_=re.compile("post|article|news|headline", re.I))
        if not containers:
            containers = soup.find_all("div", class_=re.compile("entry|item|story", re.I))
        if not containers:
            containers = soup.find_all(["h1", "h2", "h3"])

        headlines = []
        seen = set()
        for container in containers[:40]:
            headline = _extract_headline_data(container)
            if not headline:
                continue

            key = headline_dedup_key(headline)
            if key in seen:
                continue
            seen.add(key)
            headlines.append(headline)
            _vlog(f"  [ok] Found headline: {headline['title'][:60]}")

        _log(f"[News Scraper] Successfully fetched {len(headlines)} headlines")
        return headlines

    except requests.exceptions.RequestException as e:
        _log(f"[News Scraper] Error fetching CyberDaily: {str(e)}")
        return []
    except Exception as e:
        _log(f"[News Scraper] Unexpected error: {str(e)}")
        return []


def save_headlines(headlines_data):
    """Merge headlines into local storage."""
    stats = {
        "saved_new": 0,
        "total_after": 0,
        "dropped_invalid": 0,
        "deduped": 0,
        "ok": False,
    }
    try:
        Path("data").mkdir(exist_ok=True)
        lock = FileLock("data/.news.lock", timeout_seconds=FILE_LOCK_TIMEOUT_SECONDS, stale_seconds=FILE_LOCK_STALE_SECONDS)
        with lock:
            existing_headlines = []
            if os.path.exists(NEWS_FILE):
                try:
                    with open(NEWS_FILE, "r", encoding="utf-8") as f:
                        existing_data = json.load(f)
                        if isinstance(existing_data, list):
                            existing_headlines = existing_data
                        elif isinstance(existing_data, dict) and "headlines" in existing_data:
                            existing_headlines = existing_data["headlines"]
                except json.JSONDecodeError:
                    existing_headlines = []

            normalized_existing = []
            for item in existing_headlines:
                if not isinstance(item, dict):
                    stats["dropped_invalid"] += 1
                    continue
                item["fetched_at"] = _to_utc_z(item.get("fetched_at"))
                if not _is_valid_headline_record(item):
                    stats["dropped_invalid"] += 1
                    continue
                normalized_existing.append(item)

            normalized_incoming = []
            for item in headlines_data:
                if not isinstance(item, dict):
                    stats["dropped_invalid"] += 1
                    continue
                item["fetched_at"] = _to_utc_z(item.get("fetched_at"))
                if not _is_valid_headline_record(item):
                    stats["dropped_invalid"] += 1
                    continue
                normalized_incoming.append(item)

            merged = {}
            for headline in normalized_existing:
                key = headline_dedup_key(headline)
                if not key[0]:
                    continue
                merged[key] = headline

            before_merge_count = len(merged)
            for headline in normalized_incoming:
                key = headline_dedup_key(headline)
                if not key[0]:
                    continue
                if key not in merged:
                    stats["saved_new"] += 1
                merged[key] = headline

            stats["deduped"] = max(0, before_merge_count + len(normalized_incoming) - len(merged))
            merged_headlines = list(merged.values())
            merged_headlines.sort(key=lambda item: item.get("fetched_at", ""), reverse=True)
            merged_headlines = merged_headlines[:MAX_HEADLINES]

            _atomic_write_json(NEWS_FILE, merged_headlines)

        stats["total_after"] = len(merged_headlines)
        stats["ok"] = True
        _log(f"[News Scraper] Saved {stats['saved_new']} new headlines to {NEWS_FILE}")
        _log(f"[News Scraper] Total headlines in database: {len(merged_headlines)}")
        return stats

    except Exception as e:
        _log(f"[News Scraper] Error saving headlines: {str(e)}")
        return stats


def run_news_scraper():
    headlines = scrape_cyberdaily_headlines()
    stats = {
        "fetched": len(headlines),
        "saved_new": 0,
        "total_after": 0,
        "dropped_invalid": 0,
        "deduped": 0,
        "ok": True,
    }
    if headlines:
        save_stats = save_headlines(headlines)
        stats.update({k: save_stats.get(k, stats.get(k)) for k in stats.keys() if k in save_stats})
        stats["ok"] = bool(save_stats.get("ok"))
    else:
        stats["ok"] = False
    return stats


if __name__ == "__main__":
    run_news_scraper()
