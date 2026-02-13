"""Quick utility to check data files"""
import json

print("=== CVE Data ===")
with open('data/cves.json', 'r', encoding='utf-8') as f:
    cves = json.load(f)
print(f"Total CVEs: {len(cves)}")
if cves:
    print(f"First CVE ID (newest): {cves[0].get('cveMetadata', {}).get('cveId', 'N/A')}")
    print(f"Last CVE ID (oldest): {cves[-1].get('cveMetadata', {}).get('cveId', 'N/A')}")

print("\n=== News Data ===")
with open('data/cybersecurity_news.json', 'r', encoding='utf-8') as f:
    news = json.load(f)
print(f"Total headlines: {len(news)}")
if news:
    print(f"First headline: {news[0].get('title', 'N/A')[:50]}...")
    print(f"First category: {news[0].get('category', 'N/A')}")
