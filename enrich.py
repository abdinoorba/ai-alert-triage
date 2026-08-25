"""
Enrichment layer.

Takes the observables out of an alert and looks them up against threat-intel
sources. Right now it does IP reputation via AbuseIPDB. If no API key is set,
it returns MOCK data so the pipeline still runs end to end.

Add later: hash lookups (VirusTotal), domain/URL reputation, geo, etc.
"""

import os
import requests


def enrich_ip(ip):
    """Look up one IP's reputation via AbuseIPDB. Mock result if no key set."""
    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        return {
            "observable": ip,
            "source": "AbuseIPDB (mock)",
            "abuse_score": 0,
            "result": "no ABUSEIPDB_API_KEY set - using mock data",
            "mock": True,
        }

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()["data"]
        score = data.get("abuseConfidenceScore")
        return {
            "observable": ip,
            "source": "AbuseIPDB",
            "abuse_score": score,
            "total_reports": data.get("totalReports"),
            "country": data.get("countryCode"),
            "result": f"abuse score {score}/100, {data.get('totalReports')} reports",
            "mock": False,
        }
    except Exception as e:
        return {
            "observable": ip,
            "source": "AbuseIPDB",
            "result": f"lookup failed: {e}",
            "error": True,
        }


def enrich_alert(alert):
    """Enrich every enrichable observable in an alert. Returns a list of results."""
    results = []
    entities = alert.get("entities", {})

    for ip in entities.get("source_ips", []):
        results.append(enrich_ip(ip))

    # TODO (phase 2): enrich file_hashes via VirusTotal, domains/urls, etc.

    return results
