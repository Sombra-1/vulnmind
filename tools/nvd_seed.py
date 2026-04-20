"""
nvd_seed.py — NVD API bulk fetch for KB expansion.

Fetches CVE data for a list of products/services from the National Vulnerability
Database API 2.0, dumps them to tools/staging/nvd_extracted.json, and hands off
to merge_kb.py for validation and merge into vulnmind/knowledge/services.json.

This is a *build-time* tool — for runtime CVE enrichment see vulnmind/nvd.py,
which hits NVD live under `--deep`.

Usage:
  python tools/nvd_seed.py
"""

import requests
import json
import time
from pathlib import Path

# NVD API 2.0 Base URL
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

TARGET_PRODUCTS = [
    {"service": "http", "keyword": "apache http_server"},
    {"service": "ssh", "keyword": "openssh"},
    {"service": "redis", "keyword": "redis"},
    {"service": "mongodb", "keyword": "mongodb"},
]

OUT_FILE = Path(__file__).parent / "staging" / "nvd_extracted.json"

def fetch_cves(keyword, max_results=5):
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
        "noRejected": "",
        "cvssV3Severity": "CRITICAL" # Only fetch criticals to start
    }
    
    print(f"Fetching NVD data for: {keyword}...")
    headers = {
        "User-Agent": "VulnMind Seed Script"
    }
    
    try:
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json().get("vulnerabilities", [])
    except Exception as e:
        print(f"Error fetching data for {keyword}: {e}")
        return []

def extract_cve_data(vuln_data, service_name):
    cve = vuln_data.get("cve", {})
    cve_id = cve.get("id")
    
    # Get description
    descriptions = cve.get("descriptions", [])
    desc_text = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
    
    if len(desc_text) < 30:
        desc_text = desc_text.ljust(30, ".")
        
    return {
        "product": None, # Complex to extract CPE exact matches automatically, manual review needed later
        "version_match": None,
        "version_before": None,
        "priority": "critical",
        "cves": [cve_id],
        "description": desc_text,
        "suggested_commands": [],
        "metasploit_modules": []
    }

def main():
    results = {}
    
    for target in TARGET_PRODUCTS:
        service = target["service"]
        keyword = target["keyword"]
        
        vulns = fetch_cves(keyword)
        if service not in results:
            results[service] = []
            
        for vuln in vulns:
            entry = extract_cve_data(vuln, service)
            results[service].append(entry)
            
        # NVD API rate limits without key: 5 requests per 30 seconds
        time.sleep(6)
        
    with open(OUT_FILE, "w") as f:
        json.dump(results, f, indent=2)
        
    print(f"Saved {sum(len(v) for v in results.values())} entries to {OUT_FILE}")
    print("Don't forget to update merge_kb.py to include nvd_extracted.json if you want to merge it automatically.")

if __name__ == "__main__":
    main()
