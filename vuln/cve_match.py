"""
vuln/cve_match.py
Correlates detected service/version strings against real CVE data:

1. searchsploit  -> finds known exploit-db PoCs for the product/version
2. NVD REST API  -> pulls the actual CVE list + real CVSS base score for the
                     product/version (https://services.nvd.nist.gov/rest/json/cves/2.0)

Severity is derived strictly from the CVSS base score returned by NVD —
no guessing, no "exploit found = High" shortcuts.

Performance: NVD lookups run concurrently via a thread pool, gated by a
sliding-window RateLimiter so multiple services are queried in parallel
without exceeding NVD's actual rate limit (5 req/30s unauthenticated,
~50 req/30s with an API key) — instead of blocking on a sleep() per call
one at a time. A local cache (utils/cache.py) also skips the network call
entirely for a product/version already looked up recently.
"""

import subprocess
import json
import urllib.request
import urllib.parse
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logger import get_logger
from utils.cache import NVDCache
from utils.rate_limiter import RateLimiter
from vuln.vulners_client import query_vulners_for_cve
from vuln.risk_enrichment import enrich_cve

log = get_logger("cve_match")

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# NVD's published rate limits: 5 requests/30s unauthenticated, 50 requests/30s with a key.
UNAUTH_RATE = (5, 30)
AUTH_RATE = (50, 30)

# How many NVD queries to run concurrently. Kept modest even with a key —
# NVD's limit is a rolling window, not a hard concurrency cap, but going
# too wide risks bursts that still trip the limiter.
MAX_WORKERS_UNAUTH = 3
MAX_WORKERS_AUTH = 8


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
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            return entries[0]["cvssData"]["baseScore"]
    return None


def _query_nvd_uncached(product: str, version: str, api_key: str, rate_limiter: RateLimiter) -> list:
    """Actual NVD HTTP call, gated by the shared rate limiter. Not called directly — see query_nvd()."""
    keyword = f"{product} {version}".strip()
    params = {"keywordSearch": keyword, "resultsPerPage": 10}
    url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"

    headers = {"User-Agent": "ReconToReport/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    req = urllib.request.Request(url, headers=headers)

    rate_limiter.acquire()  # blocks here until a slot is free, doesn't hold up other threads' turns unfairly

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

    results = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        metrics = cve.get("metrics", {})
        score = _extract_cvss(metrics)
        descriptions = cve.get("descriptions", [])
        desc_text = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        results.append({
            "cve_id": cve.get("id"),
            "cvss_score": score,
            "severity": severity_from_cvss(score),
            "description": desc_text[:300],
            "published": cve.get("published"),
        })

    return results


def query_nvd(product: str, version: str, api_key: str, rate_limiter: RateLimiter, cache: NVDCache) -> list:
    """Cache-first NVD lookup. Falls through to the real API call on a cache miss."""
    if not product:
        return []

    cached = cache.get(product, version)
    if cached is not None:
        return cached

    results = _query_nvd_uncached(product, version, api_key, rate_limiter)
    cache.set(product, version, results)
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


def _correlate_one(svc: dict, api_key: str, rate_limiter: RateLimiter, cache: NVDCache,
                    vulners_api_key: str = None) -> dict:
    product = svc.get("product", "")
    version = svc.get("version", "")

    cves = query_nvd(product, version, api_key, rate_limiter, cache)
    exploits = query_searchsploit(product, version)

    if cves:
        scored = [c for c in cves if c["cvss_score"] is not None]
        top = max(scored, key=lambda c: c["cvss_score"]) if scored else None
        severity = top["severity"] if top else "Unknown"
        top_score = top["cvss_score"] if top else None
    else:
        top = None
        severity = "Info"
        top_score = None

    # Vulners enrichment: only for the highest-severity CVE on this service,
    # to keep total API calls proportional to services rather than every CVE.
    vulners_exploits = []
    risk_enrichment = {"epss": {"score": None, "percentile": None},
                        "cisa_kev": {"in_kev": False, "date_added": None, "ransomware_use": None}}
    if top:
        if vulners_api_key:
            vulners_exploits = query_vulners_for_cve(top["cve_id"], vulners_api_key)
        risk_enrichment = enrich_cve(top["cve_id"])  # EPSS + CISA KEV, both free/no-key

    return {
        "port": svc.get("port"),
        "service": svc.get("service"),
        "product": product,
        "version": version,
        "cve_matches": cves,
        "cve_count": len(cves),
        "top_cvss_score": top_score,
        "top_cve_id": top["cve_id"] if top else None,
        "severity": severity,
        "exploit_count": len(exploits),
        "exploits": exploits[:5],
        "vulners_exploits": vulners_exploits,  # [{title, source, url, type}, ...] for the top CVE
        "epss": risk_enrichment["epss"],        # {"score": 0-1, "percentile": 0-1} for the top CVE
        "cisa_kev": risk_enrichment["cisa_kev"],  # {"in_kev": bool, "date_added": ..., "ransomware_use": ...}
    }


def correlate_cves(services: list, nvd_api_key: str = None, vulners_api_key: str = None) -> list:
    """
    For each detected service, correlate against NVD + searchsploit concurrently,
    and (if a Vulners key is set) enrich the top CVE per service with exploit/PoC
    links aggregated from 200+ sources (Exploit-DB, Metasploit, GitHub, etc.) —
    broader coverage than searchsploit's Exploit-DB-only view.
    Uses a shared rate limiter so parallelism never exceeds NVD's actual rate
    limit, and a local cache so repeat product/version pairs skip the network
    call entirely. Returns findings sorted highest-severity-first.
    """
    named_services = [s for s in services if s.get("product")]
    if not named_services:
        return []

    max_calls, period = AUTH_RATE if nvd_api_key else UNAUTH_RATE
    rate_limiter = RateLimiter(max_calls=max_calls, period_seconds=period)
    cache = NVDCache()
    max_workers = MAX_WORKERS_AUTH if nvd_api_key else MAX_WORKERS_UNAUTH

    log.info(f"Correlating {len(named_services)} service(s) against NVD "
             f"({'authenticated' if nvd_api_key else 'unauthenticated'} rate limit, "
             f"{max_workers} concurrent workers)"
             + (", Vulners exploit enrichment enabled" if vulners_api_key else ""))

    findings = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_correlate_one, svc, nvd_api_key, rate_limiter, cache, vulners_api_key): svc
            for svc in named_services
        }
        for future in as_completed(futures):
            svc = futures[future]
            try:
                findings.append(future.result())
            except Exception as e:
                log.warning(f"CVE correlation failed for port {svc.get('port')}: {e}")

    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, "Unknown": 5, "None": 6}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 5))

    return findings