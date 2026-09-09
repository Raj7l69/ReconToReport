"""
modules/web_enum.py
Directory brute-force via gobuster, basic tech detection via whatweb,
optional screenshot capture, and basic OWASP-style reflected-input probing
(SQLi error-based, XSS reflection) against discovered URL parameters.

NOTE on the OWASP probes: these are lightweight, non-destructive checks —
they send a handful of known error-triggering / reflection-testing payloads
and look for tell-tale signs (DB error strings, unescaped payload reflection).
They are meant to flag "worth investigating manually" candidates, not to
serve as a full scanner. Only run against targets you're authorized to test.
"""

import subprocess
import re
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path
from utils.logger import get_logger

log = get_logger("web_enum")

# Common DB error signatures for basic error-based SQLi detection
SQL_ERROR_SIGNATURES = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"sqlite3\.OperationalError",
    r"pg_query\(\)",
    r"ORA-\d{5}",
    r"Microsoft OLE DB Provider for SQL Server",
]

SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "1' ORDER BY 1--"]
XSS_PAYLOAD = "<script>ReconToReportXSSPROBE</script>"


def run_gobuster(url: str, outdir: Path, wordlist: str) -> Path:
    out_file = outdir / f"gobuster_{url.split('//')[-1].replace(':', '_').replace('/', '_')}.txt"
    cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-o", str(out_file), "-q"]
    log.info(f"Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except FileNotFoundError:
        log.warning("gobuster not found. Install it: sudo apt install gobuster")
        return None
    except subprocess.TimeoutExpired:
        log.warning(f"gobuster timed out for {url}")
    return out_file if out_file.exists() else None


def run_whatweb(url: str, outdir: Path) -> Path:
    out_file = outdir / f"whatweb_{url.split('//')[-1].replace(':', '_').replace('/', '_')}.txt"
    cmd = ["whatweb", url]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        out_file.write_text(result.stdout)
    except FileNotFoundError:
        log.warning("whatweb not found. Install it: sudo apt install whatweb")
        return None
    except subprocess.TimeoutExpired:
        log.warning(f"whatweb timed out for {url}")
        return None
    return out_file


def capture_screenshot(url: str, outdir: Path) -> Path:
    screenshots_dir = outdir / "screenshots"
    screenshots_dir.mkdir(exist_ok=True)
    cmd = ["gowitness", "single", url, "--screenshot-path", str(screenshots_dir)]
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except FileNotFoundError:
        log.warning("gowitness not found. Install it: https://github.com/sensepost/gowitness. Skipping screenshot.")
        return None
    except subprocess.TimeoutExpired:
        log.warning(f"Screenshot capture timed out for {url}")
        return None
    return screenshots_dir


def _fetch(url: str) -> str:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "ReconToReport/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.read().decode(errors="ignore")
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
        log.debug(f"Fetch failed for {url}: {e}")
        return ""


def probe_sqli(url: str, param: str) -> dict:
    """Send known SQLi-triggering payloads to a single parameter, look for DB error signatures."""
    for payload in SQLI_PAYLOADS:
        test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
        body = _fetch(test_url)
        for sig in SQL_ERROR_SIGNATURES:
            if re.search(sig, body, re.IGNORECASE):
                return {"vulnerable": True, "payload": payload, "matched_signature": sig, "param": param}
    return {"vulnerable": False, "param": param}


def probe_xss(url: str, param: str) -> dict:
    """Send a script payload, check whether it's reflected unescaped in the response."""
    test_url = f"{url}?{param}={urllib.parse.quote(XSS_PAYLOAD)}"
    body = _fetch(test_url)
    reflected = XSS_PAYLOAD in body
    return {"vulnerable": reflected, "param": param, "payload": XSS_PAYLOAD}


def run_owasp_probes(url: str, params: list = None) -> dict:
    """
    Run basic SQLi/XSS reflection probes against a list of parameter names.
    If no params are given, tries a small set of common ones (id, search, q, page).

    These are heuristic, low-confidence signals meant to flag candidates for
    manual verification — not a replacement for a proper scanner (e.g. sqlmap, Burp).
    """
    test_params = params or ["id", "search", "q", "page", "user"]
    sqli_results = [probe_sqli(url, p) for p in test_params]
    xss_results = [probe_xss(url, p) for p in test_params]

    return {
        "sqli_findings": [r for r in sqli_results if r["vulnerable"]],
        "xss_findings": [r for r in xss_results if r["vulnerable"]],
        "params_tested": test_params,
    }


def run_web_enum(url: str, outdir: Path, wordlist: str, screenshot: bool = False) -> dict:
    result = {
        "url": url,
        "gobuster_output": None,
        "whatweb_output": None,
        "screenshot_dir": None,
        "owasp_probes": None,
    }

    gobuster_file = run_gobuster(url, outdir, wordlist)
    if gobuster_file:
        result["gobuster_output"] = str(gobuster_file)

    whatweb_file = run_whatweb(url, outdir)
    if whatweb_file:
        result["whatweb_output"] = str(whatweb_file)

    if screenshot:
        shot_dir = capture_screenshot(url, outdir)
        if shot_dir:
            result["screenshot_dir"] = str(shot_dir)

    log.info(f"Running basic OWASP probes (SQLi/XSS) on {url}")
    result["owasp_probes"] = run_owasp_probes(url)

    return result
