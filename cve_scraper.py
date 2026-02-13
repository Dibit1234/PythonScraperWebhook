"""Fetch the most recent CVEs from CVEProject and store them locally."""

import json
import os
import re
import tempfile
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

CVSS_PRIORITY = ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0")
MAX_DETAIL_CHUNKS = 6
MAX_CHUNK_LENGTH = 220


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


def _split_text_chunks(text, max_chunk_length=MAX_CHUNK_LENGTH):
    if not text:
        return []
    sentence_like = re.split(r"(?<=[.!?])\s+", " ".join(text.split()))
    chunks = []
    for sentence in sentence_like:
        s = sentence.strip()
        if not s:
            continue
        while len(s) > max_chunk_length:
            chunks.append(s[:max_chunk_length].rstrip())
            s = s[max_chunk_length:].lstrip()
        if s:
            chunks.append(s)
    return chunks


def _extract_problem_types(cna):
    problem_types = []
    for item in cna.get("problemTypes", []):
        for desc in item.get("descriptions", []):
            text = desc.get("description") or desc.get("cweId")
            if not text:
                continue
            cleaned = " ".join(str(text).split())
            if cleaned and cleaned not in problem_types:
                problem_types.append(cleaned)
    return problem_types


def _extract_targets(cna):
    targets = []
    for affected in cna.get("affected", []):
        vendor = (affected.get("vendor") or "").strip()
        product = (affected.get("product") or "").strip()
        versions = []
        for version in affected.get("versions", [])[:3]:
            v = version.get("version")
            if v:
                versions.append(str(v).strip())

        parts = [p for p in [vendor, product] if p]
        if versions:
            parts.append(f"versions: {', '.join(versions)}")

        text = " | ".join(parts).strip(" |")
        if text and text not in targets:
            targets.append(text)
    return targets


def _extract_primary_description(cna):
    descriptions = cna.get("descriptions", [])
    if not descriptions:
        return ""
    for item in descriptions:
        value = item.get("value")
        if value:
            return " ".join(str(value).split())
    return ""


def _extract_recommendations_from_text(description):
    recommendations = []
    for sentence in re.split(r"(?<=[.!?])\s+", description):
        s = sentence.strip()
        if not s:
            continue
        lower = s.lower()
        if any(word in lower for word in ("recommend", "patch", "upgrade", "mitigate", "apply", "fix")):
            recommendations.append(s)
    return recommendations


def _severity_from_score(score):
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def _select_best_cvss(cna):
    best = None
    for metric in cna.get("metrics", []):
        for key in CVSS_PRIORITY:
            payload = metric.get(key)
            if not isinstance(payload, dict):
                continue

            score = payload.get("baseScore")
            try:
                score = float(score) if score is not None else None
            except (TypeError, ValueError):
                score = None

            candidate = {
                "key": key,
                "version": payload.get("version", key.replace("cvssV", "").replace("_", ".")),
                "score": score,
                "severity": payload.get("baseSeverity"),
                "vector": payload.get("vectorString"),
            }

            if best is None:
                best = candidate
                continue

            current_rank = CVSS_PRIORITY.index(candidate["key"])
            best_rank = CVSS_PRIORITY.index(best["key"])
            if current_rank < best_rank:
                best = candidate
            elif current_rank == best_rank and (candidate["score"] or -1) > (best["score"] or -1):
                best = candidate

    if best is None:
        return {
            "version": "",
            "score": None,
            "severity": "UNKNOWN",
            "vector": "",
        }

    if not best.get("severity"):
        best["severity"] = _severity_from_score(best.get("score"))

    return {
        "version": best["version"] or "",
        "score": best["score"],
        "severity": best["severity"] or "UNKNOWN",
        "vector": best.get("vector") or "",
    }


def _build_compact_summary(cve):
    cna = cve.get("containers", {}).get("cna", {})
    title = " ".join(str(cna.get("title", "")).split()).strip()
    primary_description = _extract_primary_description(cna)
    problem_types = _extract_problem_types(cna)
    targets = _extract_targets(cna)
    recommendations = _extract_recommendations_from_text(primary_description)
    cvss = _select_best_cvss(cna)

    details = []
    if problem_types:
        details.append(f"Issue types: {', '.join(problem_types[:4])}")
    details.extend(_split_text_chunks(primary_description))
    if targets:
        details.append(f"Targets: {', '.join(targets[:3])}")
    if recommendations:
        details.extend(recommendations[:2])

    deduped_details = []
    seen = set()
    for item in details:
        key = item.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        deduped_details.append(item)

    details = deduped_details[:MAX_DETAIL_CHUNKS]
    if not details and primary_description:
        details = [primary_description[:MAX_CHUNK_LENGTH]]

    return {
        "title": title or cve.get("cveMetadata", {}).get("cveId", ""),
        "level": cvss["severity"],
        "cvss": cvss,
        "problem_types": problem_types[:6],
        "targets": targets[:6],
        "details": details,
    }


def compact_cve_record(cve):
    metadata = cve.get("cveMetadata", {})
    compact = {
        "cveMetadata": {
            "cveId": metadata.get("cveId"),
            "state": metadata.get("state", ""),
            "dateReserved": metadata.get("dateReserved", ""),
            "datePublished": metadata.get("datePublished", ""),
            "dateUpdated": metadata.get("dateUpdated", ""),
            "timeUpdated": metadata.get("timeUpdated", ""),
        },
        "_fetched_at": cve.get("_fetched_at", datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")),
    }

    if "summary" in cve and isinstance(cve.get("summary"), dict):
        summary = cve["summary"]
        details = summary.get("details", [])
        normalized_details = []
        seen = set()
        for item in details:
            if not isinstance(item, str):
                continue
            text = " ".join(item.split())
            key = text.lower()
            if not text or key in seen:
                continue
            seen.add(key)
            normalized_details.append(text[:MAX_CHUNK_LENGTH])

        compact["summary"] = {
            "title": summary.get("title", compact["cveMetadata"]["cveId"]),
            "level": summary.get("level", "UNKNOWN"),
            "cvss": summary.get("cvss", {"version": "", "score": None, "severity": "UNKNOWN", "vector": ""}),
            "problem_types": summary.get("problem_types", [])[:6],
            "targets": summary.get("targets", [])[:6],
            "details": normalized_details[:MAX_DETAIL_CHUNKS],
        }
        return compact

    compact["summary"] = _build_compact_summary(cve)
    return compact


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
                        cves_data.append(compact_cve_record(format_cve_dates(cve_json)))
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

        existing_cves = [compact_cve_record(format_cve_dates(cve)) for cve in existing_cves if _is_valid_cve_record(cve)]
        incoming_cves = [compact_cve_record(format_cve_dates(cve)) for cve in cves_data if _is_valid_cve_record(cve)]

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

        _atomic_write_json(DATA_FILE, sorted_cves)

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
