"""Fetch the most recent CVEs from CVEProject and store them locally."""

import json
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import requests

DATA_FILE = "data/cves.json"
GITHUB_API_BASE = "https://api.github.com/repos/CVEProject/cvelistV5/contents"
ALLOWED_JSON_HOSTS = {"api.github.com", "raw.githubusercontent.com"}
MAX_JSON_BYTES = 6_000_000
MAX_CVES = 10
ISO_DATE_FORMATS = ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z")
COMPACT_DATE_FORMAT = "%d-%m-%Y"
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
UNAUTHENTICATED_MIN_REQUEST_INTERVAL_SECONDS = 1.0
AUTHENTICATED_MIN_REQUEST_INTERVAL_SECONDS = 0.05
# The scheduler can execute 5 runs within a rolling 60-minute window
# (immediate startup run + every 15 minutes), so keep this <= 100.
GITHUB_MAX_API_CALLS_PER_RUN = 80
MAX_RATE_LIMIT_WAIT_SECONDS = 30

_SESSION = requests.Session()
_LAST_GITHUB_REQUEST_TS = 0.0
_GITHUB_API_CALLS_THIS_RUN = 0


def _has_github_token():
    return bool(os.getenv("GITHUB_TOKEN"))


def _min_request_interval_seconds():
    if _has_github_token():
        return AUTHENTICATED_MIN_REQUEST_INTERVAL_SECONDS
    return UNAUTHENTICATED_MIN_REQUEST_INTERVAL_SECONDS


def _reset_github_rate_state():
    global _LAST_GITHUB_REQUEST_TS, _GITHUB_API_CALLS_THIS_RUN
    _LAST_GITHUB_REQUEST_TS = 0.0
    _GITHUB_API_CALLS_THIS_RUN = 0


def _throttle_if_needed():
    global _LAST_GITHUB_REQUEST_TS
    now = time.time()
    min_interval = _min_request_interval_seconds()
    elapsed = now - _LAST_GITHUB_REQUEST_TS
    if elapsed < min_interval:
        time.sleep(min_interval - elapsed)
    _LAST_GITHUB_REQUEST_TS = time.time()


def _consume_api_call_budget():
    global _GITHUB_API_CALLS_THIS_RUN
    _GITHUB_API_CALLS_THIS_RUN += 1
    if _GITHUB_API_CALLS_THIS_RUN > GITHUB_MAX_API_CALLS_PER_RUN:
        raise RuntimeError(
            f"Reached per-run GitHub API budget ({GITHUB_MAX_API_CALLS_PER_RUN}). "
            "Set GITHUB_TOKEN for higher throughput."
        )


def _rate_limit_wait_seconds(response):
    remaining = response.headers.get("X-RateLimit-Remaining")
    reset_epoch = response.headers.get("X-RateLimit-Reset")
    if remaining != "0" or not reset_epoch:
        return None

    try:
        reset_ts = int(reset_epoch)
    except ValueError:
        return None
    now = int(time.time())
    return max(reset_ts - now + 1, 1)


def _is_allowed_url(url, allowed_hosts):
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return False
    host = (parsed.hostname or "").lower()
    return host in allowed_hosts


def _request_json(url, timeout=10):
    if not _is_allowed_url(url, ALLOWED_JSON_HOSTS):
        raise ValueError(f"Blocked URL: {url}")

    headers = {"Accept": "application/json"}
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    for attempt in range(2):
        _consume_api_call_budget()
        _throttle_if_needed()
        response = _SESSION.get(url, timeout=timeout, headers=headers)

        wait_seconds = _rate_limit_wait_seconds(response)
        if response.status_code == 403 and wait_seconds:
            if wait_seconds <= MAX_RATE_LIMIT_WAIT_SECONDS and attempt == 0:
                print(f"[CVE Scraper] GitHub rate limit hit, waiting {wait_seconds}s before retry...")
                time.sleep(wait_seconds)
                continue
            raise RuntimeError(
                "GitHub API rate limit exceeded. "
                "Set GITHUB_TOKEN or retry after reset."
            )

        response.raise_for_status()
        break

    final_url = response.url or url
    if not _is_allowed_url(final_url, ALLOWED_JSON_HOSTS):
        raise ValueError(f"Blocked redirect: {final_url}")

    content_type = (response.headers.get("Content-Type") or "").lower()
    if "json" not in content_type and "text/plain" not in content_type:
        raise ValueError(f"Unexpected content type: {content_type}")

    if len(response.content) > MAX_JSON_BYTES:
        raise ValueError("Payload too large")

    return response.json()


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
        pass

    for fmt in ISO_DATE_FORMATS:
        try:
            return datetime.strptime(normalized, fmt)
        except ValueError:
            continue
    return None


def _parse_date_with_optional_time(date_str, time_str="00:00:00"):
    if not date_str or not isinstance(date_str, str):
        return None

    parsed_iso = _parse_iso_datetime(date_str)
    if parsed_iso:
        return parsed_iso

    try:
        return datetime.strptime(f"{date_str} {time_str}", f"{COMPACT_DATE_FORMAT} %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _cve_sort_key(cve):
    metadata = cve.get("cveMetadata", {})

    published_dt = _parse_date_with_optional_time(metadata.get("datePublished"))
    if published_dt:
        return published_dt

    reserved_dt = _parse_date_with_optional_time(metadata.get("dateReserved"))
    if reserved_dt:
        return reserved_dt

    updated_dt = _parse_date_with_optional_time(metadata.get("dateUpdated"), metadata.get("timeUpdated", "00:00:00"))
    if updated_dt:
        return updated_dt

    provider_dt = _parse_iso_datetime(
        cve.get("containers", {}).get("cna", {}).get("providerMetadata", {}).get("dateUpdated")
    )
    if provider_dt:
        return provider_dt

    fetched_dt = _parse_iso_datetime(cve.get("_fetched_at"))
    if fetched_dt:
        return fetched_dt

    return datetime.min.replace(tzinfo=timezone.utc)


def _is_valid_cve_record(cve):
    if not isinstance(cve, dict):
        return False
    cve_id = cve.get("cveMetadata", {}).get("cveId", "")
    return bool(CVE_ID_PATTERN.fullmatch(cve_id))


def format_cve_dates(cve):
    """Normalize CVE metadata dates for compact storage."""
    metadata = cve.get("cveMetadata")
    if not metadata:
        return cve

    updated = _parse_iso_datetime(metadata.get("dateUpdated"))
    if updated:
        metadata["dateUpdated"] = updated.strftime("%d-%m-%Y")
        metadata["timeUpdated"] = updated.strftime("%H:%M:%S")

    published = _parse_iso_datetime(metadata.get("datePublished"))
    if published:
        metadata["datePublished"] = published.strftime("%d-%m-%Y")

    reserved = _parse_iso_datetime(metadata.get("dateReserved"))
    if reserved:
        metadata["dateReserved"] = reserved.strftime("%d-%m-%Y")

    return cve


def get_recent_cves(limit=MAX_CVES):
    """Fetch recent CVEs from CVEProject."""
    try:
        print(f"[CVE Scraper] Fetching {limit} most recent CVEs from GitHub...")
        _reset_github_rate_state()
        print(
            "[CVE Scraper] Auth: "
            f"{'token detected' if _has_github_token() else 'no token'} | "
            f"API budget this run: {GITHUB_MAX_API_CALLS_PER_RUN} requests"
        )

        cves_data = []
        current_year = datetime.now().year

        for year in range(current_year, current_year - 5, -1):
            try:
                year_url = f"{GITHUB_API_BASE}/cves/{year}"
                year_items = _request_json(year_url)
                if not isinstance(year_items, list):
                    continue

                year_items.sort(key=lambda item: item.get("name", ""), reverse=True)

                for item in year_items:
                    if item.get("type") != "dir":
                        continue

                    dir_name = item.get("name")
                    if not dir_name:
                        continue

                    dir_url = f"{GITHUB_API_BASE}/cves/{year}/{dir_name}"
                    dir_items = _request_json(dir_url)
                    if not isinstance(dir_items, list):
                        continue

                    json_files = [
                        entry
                        for entry in dir_items
                        if entry.get("type") == "file" and entry.get("name", "").endswith(".json")
                    ]
                    json_files.sort(key=lambda entry: entry.get("name", ""), reverse=True)

                    for file_item in json_files:
                        download_url = file_item.get("download_url")
                        if not download_url:
                            continue

                        cve_json = _request_json(download_url)
                        if not _is_valid_cve_record(cve_json):
                            continue

                        cve_json["_fetched_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                        cves_data.append(format_cve_dates(cve_json))
                        print(
                            f"  [ok] Fetched CVE from {year}/{dir_name}/{file_item.get('name', '')}"
                        )

                        if len(cves_data) >= limit:
                            break

                    if len(cves_data) >= limit:
                        break

            except Exception as e:
                print(f"[CVE Scraper] Skipping year {year}: {e}")
                if "rate limit exceeded" in str(e).lower():
                    break
                continue

        cves_data.sort(key=_cve_sort_key, reverse=True)
        print(f"[CVE Scraper] Successfully fetched {len(cves_data)} CVEs")
        return cves_data[:limit]

    except requests.exceptions.RequestException as e:
        print(f"[CVE Scraper] Error fetching CVEs: {str(e)}")
        return []


def save_cves(cves_data):
    """Merge CVEs into local storage, newest first."""
    try:
        Path("data").mkdir(exist_ok=True)

        existing_cves = []
        if os.path.exists(DATA_FILE):
            try:
                with open(DATA_FILE, "r", encoding="utf-8") as f:
                    existing_data = json.load(f)
                    if isinstance(existing_data, list):
                        existing_cves = existing_data
                    elif isinstance(existing_data, dict) and "cves" in existing_data:
                        existing_cves = existing_data["cves"]
            except json.JSONDecodeError:
                existing_cves = []

        existing_cves = [cve for cve in existing_cves if _is_valid_cve_record(cve)]
        incoming_cves = [cve for cve in cves_data if _is_valid_cve_record(cve)]

        merged_by_id = {}
        for cve in existing_cves:
            merged_by_id[cve["cveMetadata"]["cveId"]] = cve

        new_cves_added = 0
        for cve in incoming_cves:
            cve_id = cve["cveMetadata"]["cveId"]
            if cve_id not in merged_by_id:
                new_cves_added += 1
            merged_by_id[cve_id] = cve

        sorted_cves = sorted(merged_by_id.values(), key=_cve_sort_key, reverse=True)[:MAX_CVES]

        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(sorted_cves, f, indent=2, ensure_ascii=False)

        print(f"[CVE Scraper] Saved {new_cves_added} new CVEs to {DATA_FILE}")
        print(f"[CVE Scraper] Total CVEs in database (most recent): {len(sorted_cves)}")
        return True

    except Exception as e:
        print(f"[CVE Scraper] Error saving CVEs: {str(e)}")
        return False


def run_cve_scraper():
    cves = get_recent_cves(limit=MAX_CVES)
    if cves:
        save_cves(cves)
    return cves


if __name__ == "__main__":
    run_cve_scraper()
