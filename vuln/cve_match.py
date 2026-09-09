"""
vuln/cve_match.py
Correlates detected service/version strings against real CVE data:

1. searchsploit  -> finds known exploit-db PoCs for the product/version
2. NVD REST API  -> pulls the actual CVE list + real CVSS base score for the
                     product/version (https://services.nvd.nist.gov/rest/json/cves/2.0)

Severity is derived strictly from the CVSS base score returned by NVD —
no guessing, no "exploit found = High" shortcuts.
"""

import subprocess
import json
import time
import urllib.request
import urllib.parse
import urllib.error
from utils.logger import get_logger

log = get_logger("cve_match")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD's public rate limit without an API key is 5 requests / 30s.
# We sleep between calls to stay under that.
NVD_REQUEST_DELAY_SECONDS = 6


def severity_from_cvss(score: float) -> str:
    """Map a CVSS base score to a severity label using the official CVSS v3.x ranges."""
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "None"


def _extract_cvss(metrics: dict) -> float:
    """
    NVD returns CVSS under one of cvssMetricV31 / cvssMetricV30 / cvssMetricV2.
    Prefer the newest version available.
    """
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            return entries[0]["cvssData"]["baseScore"]
    return None


def query_nvd(product: str, version: str, api_key: str = None) -> list:
    """
    Query the NVD REST API for CVEs matching a product/version keyword search.
    Returns a list of {cve_id, cvss_score, severity, description, published}.
    """
    if not product:
        return []

    keyword = f"{product} {version}".strip()
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 10,
    }
    url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"

    headers = {"User-Agent": "ReconToReport/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    req = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        log.warning(f"NVD API HTTP error for '{keyword}': {e.code} {e.reason}")
        return []
    except urllib.error.URLError as e:
        log.warning(f"NVD API unreachable for '{keyword}': {e.reason}")
        return []
    except (json.JSONDecodeError, KeyError) as e:
        log.warning(f"NVD API returned unexpected data for '{keyword}': {e}")
        return []
    finally:
        # Respect NVD rate limits regardless of success/failure
        time.sleep(NVD_REQUEST_DELAY_SECONDS if not api_key else 0.6)

    results = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id")
        metrics = cve.get("metrics", {})
        score = _extract_cvss(metrics)

        descriptions = cve.get("descriptions", [])
        desc_text = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        results.append({
            "cve_id": cve_id,
            "cvss_score": score,
            "severity": severity_from_cvss(score),
            "description": desc_text[:300],
            "published": cve.get("published"),
        })

    return results


def query_searchsploit(product: str, version: str) -> list:
    """Query searchsploit for exploit-db PoCs matching the product/version."""
    if not product:
        return []

    query = f"{product} {version}".strip()
    cmd = ["searchsploit", "--json", query]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        data = json.loads(result.stdout) if result.stdout else {}
        return data.get("RESULTS_EXPLOIT", [])
    except FileNotFoundError:
        log.warning("searchsploit not found. Install: sudo apt install exploitdb")
        return []
    except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
        log.warning(f"searchsploit query failed for '{query}': {e}")
        return []


def correlate_cves(services: list, nvd_api_key: str = None) -> list:
    """
    For each detected service:
      1. Query NVD for matching CVEs + real CVSS scores
      2. Query searchsploit for matching public exploit PoCs
      3. Assign severity strictly from the highest CVSS score returned by NVD

    Returns findings sorted highest-severity-first.
    """
    findings = []

    for svc in services:
        product = svc.get("product", "")
        version = svc.get("version", "")
        if not product:
            continue

        cves = query_nvd(product, version, api_key=nvd_api_key)
        exploits = query_searchsploit(product, version)

        if cves:
            scored = [c for c in cves if c["cvss_score"] is not None]
            top = max(scored, key=lambda c: c["cvss_score"]) if scored else None
            severity = top["severity"] if top else "Unknown"
            top_score = top["cvss_score"] if top else None
        else:
            severity = "Info"  # no CVE match found — nothing to score
            top_score = None

        findings.append({
            "port": svc.get("port"),
            "service": svc.get("service"),
            "product": product,
            "version": version,
            "cve_matches": cves,
            "cve_count": len(cves),
            "top_cvss_score": top_score,
            "severity": severity,
            "exploit_count": len(exploits),
            "exploits": exploits[:5],
        })

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Unknown": 5, "None": 6}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 5))

    return findings
