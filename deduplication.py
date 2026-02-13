"""Utilities for deduplication and canonical key generation."""

import json
import os
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

TRACKING_PARAMS = {
    "fbclid",
    "gclid",
    "igshid",
    "mc_cid",
    "mc_eid",
    "mkt_tok",
}


def deduplicate_cves(cves_list):
    """
    Remove duplicate CVEs from a list based on CVE ID
    
    Args:
        cves_list (list): List of CVE dictionaries
    
    Returns:
        list: Deduplicated list of CVEs
    """
    seen_ids = set()
    deduplicated = []
    
    for cve in cves_list:
        cve_id = cve.get('cveMetadata', {}).get('cveId')
        if cve_id and cve_id not in seen_ids:
            deduplicated.append(cve)
            seen_ids.add(cve_id)
    
    return deduplicated


def canonicalize_title(title):
    """Normalize title for stable dedup checks."""
    if not isinstance(title, str):
        return ""
    return re.sub(r"\s+", " ", title).strip().lower()


def canonicalize_url(url):
    """Normalize URL for stable dedup checks."""
    if not isinstance(url, str):
        return ""

    raw = url.strip()
    if not raw:
        return ""

    parsed = urlparse(raw)
    scheme = parsed.scheme.lower() if parsed.scheme else "https"
    netloc = parsed.netloc.lower()
    path = re.sub(r"/{2,}", "/", parsed.path or "/")

    # Keep non-tracking query params only.
    filtered_pairs = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        lower_key = key.lower()
        if lower_key.startswith("utm_") or lower_key in TRACKING_PARAMS:
            continue
        filtered_pairs.append((key, value))
    query = urlencode(filtered_pairs, doseq=True)

    # Canonical trailing slash behavior.
    if path != "/" and path.endswith("/"):
        path = path[:-1]

    return urlunparse((scheme, netloc, path, "", query, ""))


def headline_dedup_key(item):
    """Canonical dedup key for headline records."""
    return (
        canonicalize_title(item.get("title", "")),
        canonicalize_url(item.get("link", "")),
    )


def deduplicate_headlines(headlines_list):
    """
    Remove duplicate headlines based on title and link
    
    Args:
        headlines_list (list): List of headline dictionaries
    
    Returns:
        list: Deduplicated list of headlines
    """
    seen_entries = set()
    deduplicated = []

    # Input is expected newest -> oldest, so first seen is preserved.
    for headline in headlines_list:
        unique_key = headline_dedup_key(headline)
        if unique_key in seen_entries:
            continue
        deduplicated.append(headline)
        seen_entries.add(unique_key)

    return deduplicated


def remove_duplicate_entries_from_file(file_path, content_type='headlines'):
    """
    Read a JSON file, remove duplicates, and save it back
    
    Args:
        file_path (str): Path to the JSON file
        content_type (str): Type of content - 'cves' or 'headlines'
    
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        if not os.path.exists(file_path):
            return False
        
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if not isinstance(data, list):
            return False
        
        # Apply appropriate deduplication based on content type
        if content_type == 'cves':
            deduplicated = deduplicate_cves(data)
        else:  # headlines
            deduplicated = deduplicate_headlines(data)
        
        # Save deduplicated data
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(deduplicated, f, indent=2, ensure_ascii=False)
        
        return True
        
    except Exception as e:
        print(f"[Deduplication] Error: {str(e)}")
        return False


def get_duplicate_count(file_path, content_type='headlines'):
    """
    Check how many duplicates exist in a file
    
    Args:
        file_path (str): Path to the JSON file
        content_type (str): Type of content - 'cves' or 'headlines'
    
    Returns:
        int: Number of duplicate entries found
    """
    try:
        if not os.path.exists(file_path):
            return 0
        
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        if not isinstance(data, list):
            return 0
        
        original_count = len(data)
        
        if content_type == 'cves':
            deduplicated = deduplicate_cves(data)
        else:
            deduplicated = deduplicate_headlines(data)
        
        return original_count - len(deduplicated)
        
    except Exception as e:
        return 0
