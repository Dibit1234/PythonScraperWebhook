"""Scrape cybersecurity headlines from CyberDaily."""

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

NEWS_FILE = "data/cybersecurity_news.json"
CYBERDAILY_URL = "https://www.cyberdaily.au/"
ALLOWED_NEWS_HOSTS = {"www.cyberdaily.au", "cyberdaily.au"}
MAX_HTML_BYTES = 5_000_000


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
    return cleaned[:500]


def _normalize_link(link):
    if not link:
        return ""
    absolute = urljoin(CYBERDAILY_URL, link)
    parsed = urlparse(absolute)
    if parsed.scheme not in {"http", "https"}:
        return ""
    if (parsed.hostname or "").lower() not in ALLOWED_NEWS_HOSTS:
        return ""
    return absolute


def _fetch_news_page():
    if not _is_allowed_url(CYBERDAILY_URL, ALLOWED_NEWS_HOSTS):
        raise ValueError(f"Blocked URL: {CYBERDAILY_URL}")

    headers = {"User-Agent": "PythonScraperWebhook/1.0"}
    response = requests.get(CYBERDAILY_URL, headers=headers, timeout=15)
    response.raise_for_status()

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
        "title": title,
        "category": "General",
        "link": link,
        "description": description,
        "fetched_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source": "CyberDaily AU",
    }


def scrape_cyberdaily_headlines():
    """Fetch current headlines from CyberDaily."""
    try:
        print("[News Scraper] Fetching headlines from CyberDaily AU...")
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

            key = (headline["title"], headline["link"])
            if key in seen:
                continue
            seen.add(key)
            headlines.append(headline)
            print(f"  [ok] Found headline: {headline['title'][:60]}")

        print(f"[News Scraper] Successfully fetched {len(headlines)} headlines")
        return headlines

    except requests.exceptions.RequestException as e:
        print(f"[News Scraper] Error fetching CyberDaily: {str(e)}")
        return []
    except Exception as e:
        print(f"[News Scraper] Unexpected error: {str(e)}")
        return []


def save_headlines(headlines_data):
    """Merge headlines into local storage."""
    try:
        Path("data").mkdir(exist_ok=True)

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

        merged = {}
        for headline in existing_headlines:
            key = (headline.get("title", ""), headline.get("link", ""))
            merged[key] = headline

        new_headlines_added = 0
        for headline in headlines_data:
            key = (headline.get("title", ""), headline.get("link", ""))
            if not key[0]:
                continue
            if key not in merged:
                new_headlines_added += 1
            merged[key] = headline

        merged_headlines = list(merged.values())
        merged_headlines.sort(key=lambda item: item.get("fetched_at", ""), reverse=True)
        merged_headlines = merged_headlines[:500]

        with open(NEWS_FILE, "w", encoding="utf-8") as f:
            json.dump(merged_headlines, f, indent=2, ensure_ascii=False)

        print(f"[News Scraper] Saved {new_headlines_added} new headlines to {NEWS_FILE}")
        print(f"[News Scraper] Total headlines in database: {len(merged_headlines)}")
        return True

    except Exception as e:
        print(f"[News Scraper] Error saving headlines: {str(e)}")
        return False


def run_news_scraper():
    headlines = scrape_cyberdaily_headlines()
    if headlines:
        save_headlines(headlines)
    return headlines


if __name__ == "__main__":
    run_news_scraper()
