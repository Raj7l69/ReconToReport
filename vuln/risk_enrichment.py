"""
vuln/risk_enrichment.py
Adds two free, no-key data sources on top of NVD's CVSS score:

1. EPSS (Exploit Prediction Scoring System) — FIRST.org's public API.
   Gives a 0-1 probability that a CVE will actually be exploited in the
   wild in the next 30 days. CVSS measures theoretical severity; EPSS
   measures real-world exploitation likelihood — the two together give a
   much better prioritization signal than CVSS alone.

2. CISA KEV (Known Exploited Vulnerabilities Catalog) — a public JSON feed
   published by the US Cybersecurity and Infrastructure Security Agency,
   listing CVEs with CONFIRMED real-world exploitation. A CVE on this list
   isn't theoretically risky — it's actively being used by attackers right now.

Both are free and require no API key or signup.
"""

import json
import urllib.request
import urllib.error
from utils.logger import get_logger

log = get_logger("risk_enrichment")

EPSS_API_URL = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

_kev_cache = None  # module-level cache: the KEV feed is fetched once per run, not once per CVE


def query_epss(cve_id: str) -> dict:
    """
    Returns {"score": float 0-1, "percentile": float 0-1} for a CVE, or
    {"score": None, "percentile": None} if EPSS has no data for it / the
    lookup fails. Never raises — this is enrichment, not a hard dependency.
    """
    if not cve_id:
        return {"score": None, "percentile": None}

    url = f"{EPSS_API_URL}?cve={cve_id}"
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        log.debug(f"EPSS lookup failed for {cve_id}: {e}")
        return {"score": None, "percentile": None}
    except json.JSONDecodeError as e:
        log.debug(f"EPSS returned unexpected data for {cve_id}: {e}")
        return {"score": None, "percentile": None}

    results = data.get("data", [])
    if not results:
        return {"score": None, "percentile": None}

    entry = results[0]
    try:
        return {"score": float(entry.get("epss")), "percentile": float(entry.get("percentile"))}
    except (TypeError, ValueError):
        return {"score": None, "percentile": None}


def _load_kev_catalog() -> dict:
    """
    Fetches the full CISA KEV catalog once and caches it in memory for the
    rest of the run (it's one JSON file covering every known-exploited CVE,
    not something to re-fetch per CVE). Returns {cve_id: kev_entry_dict}.
    """
    global _kev_cache
    if _kev_cache is not None:
        return _kev_cache

    try:
        req = urllib.request.Request(CISA_KEV_URL, headers={"User-Agent": "ReconToReport/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode())
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        log.warning(f"Could not fetch CISA KEV catalog: {e}. KEV flagging will be skipped for this run.")
        _kev_cache = {}
        return _kev_cache
    except json.JSONDecodeError as e:
        log.warning(f"CISA KEV catalog returned unexpected data: {e}. Skipping KEV flagging.")
        _kev_cache = {}
        return _kev_cache

    vulnerabilities = data.get("vulnerabilities", [])
    _kev_cache = {v["cveID"]: v for v in vulnerabilities if v.get("cveID")}
    log.info(f"Loaded CISA KEV catalog: {len(_kev_cache)} known-exploited CVEs")
    return _kev_cache


def check_cisa_kev(cve_id: str) -> dict:
    """
    Returns {"in_kev": bool, "date_added": str|None, "ransomware_use": str|None}
    for a given CVE ID against the cached CISA KEV catalog.
    """
    if not cve_id:
        return {"in_kev": False, "date_added": None, "ransomware_use": None}

    catalog = _load_kev_catalog()
    entry = catalog.get(cve_id)
    if not entry:
        return {"in_kev": False, "date_added": None, "ransomware_use": None}

    return {
        "in_kev": True,
        "date_added": entry.get("dateAdded"),
        "ransomware_use": entry.get("knownRansomwareCampaignUse", "Unknown"),
    }


def enrich_cve(cve_id: str) -> dict:
    """Convenience wrapper: runs both EPSS and CISA KEV lookups for one CVE."""
    return {
        "epss": query_epss(cve_id),
        "cisa_kev": check_cisa_kev(cve_id),
    }