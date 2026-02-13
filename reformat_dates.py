"""
Script to reformat CVE dates in the data file
"""
import json
from datetime import datetime

def reformat_cve_dates():
    """Reformat CVE dates from ISO format to DD-MM-YYYY and separate timeUpdated"""
    
    with open('data/cves.json', 'r', encoding='utf-8') as f:
        cves = json.load(f)
    
    for cve in cves:
        if 'cveMetadata' in cve:
            metadata = cve['cveMetadata']
            
            # Handle dateUpdated
            if 'dateUpdated' in metadata:
                date_str = metadata['dateUpdated']
                # Parse ISO format date (e.g., "2026-02-13T10:28:43.123456Z")
                try:
                    dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                    # Format as DD-MM-YYYY
                    date_formatted = dt.strftime('%d-%m-%Y')
                    time_formatted = dt.strftime('%H:%M:%S')
                    
                    metadata['dateUpdated'] = date_formatted
                    metadata['timeUpdated'] = time_formatted
                except Exception as e:
                    print(f"Error formatting dateUpdated for {metadata.get('cveId', 'unknown')}: {e}")
            
            # Handle datePublished
            if 'datePublished' in metadata:
                date_str = metadata['datePublished']
                try:
                    dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                    date_formatted = dt.strftime('%d-%m-%Y')
                    
                    metadata['datePublished'] = date_formatted
                except Exception as e:
                    print(f"Error formatting datePublished for {metadata.get('cveId', 'unknown')}: {e}")
            
            # Handle dateReserved
            if 'dateReserved' in metadata:
                date_str = metadata['dateReserved']
                try:
                    dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
                    date_formatted = dt.strftime('%d-%m-%Y')
                    
                    metadata['dateReserved'] = date_formatted
                except Exception as e:
                    print(f"Error formatting dateReserved for {metadata.get('cveId', 'unknown')}: {e}")
    
    # Save formatted data
    with open('data/cves.json', 'w', encoding='utf-8') as f:
        json.dump(cves, f, indent=2, ensure_ascii=False)
    
    print("✓ CVE dates reformatted successfully")
    print("✓ Dates now in DD-MM-YYYY format")
    print("✓ timeUpdated separated as a new field")

if __name__ == "__main__":
    reformat_cve_dates()
