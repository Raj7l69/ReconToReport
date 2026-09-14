"""
vuln/vulners_client.py
Queries the Vulners API for exploit/PoC bulletins tied to a specific CVE.
Vulners aggregates 200+ sources (Exploit-DB, Metasploit, GitHub PoCs, vendor
advisories) so a single CVE lookup can surface exploits that searchsploit
(Exploit-DB only) misses.

Per Vulners' documented search API (https://docs.vulners.com/docs/api/search/),
exploit lookup is a Lucene query against /api/v3/search/lucene/ filtered to
bulletinFamily:exploit — NOT a field nested inside the plain /search/id/
CVE document. Earlier versions of this module assumed the wrong endpoint/shape
and always got an empty (or blocked) result; this version follows the
documented query format directly.

Requires a free API key (scope: "api") from https://vulners.com — set via
VULNERS_API_KEY in .env or the environment. If no key is set, this module
is silently skipped (NVD + searchsploit correlation still works fine without it).
"""

import json
import urllib.request
import urllib.error
from utils.logger import get_logger

log = get_logger("vulners")

VULNERS_LUCENE_SEARCH_URL = "https://vulners.com/api/v3/search/lucene/"


def query_vulners_for_cve(cve_id: str, api_key: str) -> list:
    """
    Search Vulners for exploit/PoC bulletins referencing a given CVE ID.
    Returns [{"title": ..., "source": ..., "url": ..., "type": ...}, ...].
    Returns [] on any failure (missing key, network error, no matches) —
    this is a supplementary enrichment, never a hard dependency.
    """
    if not api_key or not cve_id:
        return []

    payload = json.dumps({
        "query": f'bulletinFamily:exploit AND "{cve_id}"',
        "skip": 0,
        "size": 5,
        "fields": ["id", "title", "type", "bulletinFamily", "href", "published"],
    }).encode("utf-8")

    req = urllib.request.Request(
        VULNERS_LUCENE_SEARCH_URL,
        data=payload,
        headers={"Content-Type": "application/json", "X-Api-Key": api_key,
                 "User-Agent": "ReconToReport/1.0 (+https://github.com/Raj7l69/ReconToReport)"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        log.debug(f"Vulners API HTTP error for {cve_id}: {e.code} {e.reason}")
        return []
    except urllib.error.URLError as e:
        log.debug(f"Vulners API unreachable for {cve_id}: {e.reason}")
        return []
    except (json.JSONDecodeError, KeyError) as e:
        log.debug(f"Vulners API returned unexpected data for {cve_id}: {e}")
        return []

    # Vulners' documented response shape is {"total": N, "results": [...]}.
    # Some API versions/responses nest results under data.search with each
    # item's fields inside "_source" instead — handle both defensively.
    results = data.get("results")
    if results is None:
        results = data.get("data", {}).get("search", [])

    exploits = []
    for item in results:
        src = item.get("_source", item)  # unwrap _source if present, else use item directly
        href = src.get("href") or f"https://vulners.com/{src.get('type', '')}/{src.get('id', '')}"
        exploits.append({
            "title": src.get("title", "Untitled"),
            "source": src.get("bulletinFamily", src.get("type", "unknown")),
            "url": href,
            "type": src.get("type", "unknown"),
        })

    return exploits[:5]  # cap for report readability