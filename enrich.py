"""
Enrichment layer.

Takes the observables out of an alert and looks them up against threat intel.
- IPs        -> AbuseIPDB (reputation / abuse score)
- files/domains/urls -> VirusTotal (multi-engine detection)

Every lookup falls back to MOCK data when the relevant API key is not set, so the
pipeline always runs end to end. The VirusTotal calls are consolidated into one
generic function rather than a copy per observable type.
"""

import os
import base64
import requests

VT_BASE = "https://www.virustotal.com/api/v3"


# --------------------------------------------------------------------------- #
# AbuseIPDB - IP reputation
# --------------------------------------------------------------------------- #
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


# --------------------------------------------------------------------------- #
# VirusTotal - generic lookup for files (hashes), domains, and urls
# --------------------------------------------------------------------------- #
def _vt_id(kind, value):
    """VirusTotal identifies URLs by a base64url of the URL (padding stripped).
    Hashes and domains are used as-is."""
    if kind == "urls":
        return base64.urlsafe_b64encode(value.encode()).decode().strip("=")
    return value


def enrich_via_virustotal(value, kind, label=None):
    """Generic VirusTotal v3 lookup. `kind` is one of: files, domains, urls.
    Returns a normalized enrichment dict. Mock result if no key set."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    label = label or kind.rstrip("s")

    if not api_key:
        return {
            "observable": value,
            "source": "VirusTotal (mock)",
            "malicious_count": 0,
            "result": "no VIRUSTOTAL_API_KEY set - using mock data",
            "mock": True,
        }

    try:
        resp = requests.get(
            f"{VT_BASE}/{kind}/{_vt_id(kind, value)}",
            headers={"x-apikey": api_key},
            timeout=15,
        )
        if resp.status_code == 404:
            return {
                "observable": value,
                "source": "VirusTotal",
                "malicious_count": 0,
                "result": f"{label} not found in VirusTotal (unknown)",
                "mock": False,
            }
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        return {
            "observable": value,
            "source": "VirusTotal",
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "total_engines": total,
            "result": f"{malicious}/{total} engines flagged this {label} as malicious",
            "mock": False,
        }
    except Exception as e:
        return {
            "observable": value,
            "source": "VirusTotal",
            "result": f"lookup failed: {e}",
            "error": True,
        }


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def enrich_alert(alert):
    """Enrich every enrichable observable in an alert. Returns a list of results."""
    results = []
    entities = alert.get("entities", {})

    for ip in entities.get("source_ips", []):
        results.append(enrich_ip(ip))

    for h in entities.get("file_hashes", []):
        # file_hashes are objects like {"type": "sha256", "value": "..."}
        results.append(enrich_via_virustotal(h["value"], "files", label="file"))

    for domain in entities.get("domains", []):
        results.append(enrich_via_virustotal(domain, "domains", label="domain"))

    for url in entities.get("urls", []):
        results.append(enrich_via_virustotal(url, "urls", label="url"))

    return results