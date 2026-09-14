"""
modules/web_enum.py
Runs gobuster across all three relevant modes (dir, dns, vhost) one at a
time — for each mode, the user either picks a wordlist and lets it run, or
presses Enter to skip that mode entirely. Each mode that runs gets its own
separate output file. Also runs whatweb (tech fingerprinting), optional
screenshot capture, and basic OWASP-style SQLi/XSS reflection probing.

WhatWeb's role here: gobuster/dir tells you *what paths exist*, but not
*what's running the site*. WhatWeb fingerprints the tech stack (CMS,
framework, JS libraries, server software + version) from response
headers/HTML/cookies — e.g. "this is WordPress 6.2 behind Apache 2.4.41".
That's useful on its own (outdated CMS/plugin = known CVEs) and it also
tells you what to look for manually (e.g. if it's WordPress, check
/wp-admin, /wp-content/plugins/ for vulnerable plugin versions).
"""

import subprocess
import re
import random
import string
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path
from utils.logger import get_logger
from modules.dns_enum import is_ip

log = get_logger("web_enum")

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

# Real SecLists paths, grouped by which gobuster mode they're actually meant for.
# Falls back gracefully if SecLists isn't installed at the standard location.
SECLISTS_BASE = "/usr/share/seclists"

WORDLISTS_BY_MODE = {
    "dir": [
        f"{SECLISTS_BASE}/Discovery/Web-Content/common.txt",
        f"{SECLISTS_BASE}/Discovery/Web-Content/directory-list-2.3-small.txt",
        f"{SECLISTS_BASE}/Discovery/Web-Content/directory-list-2.3-medium.txt",
        f"{SECLISTS_BASE}/Discovery/Web-Content/directory-list-2.3-big.txt",
        f"{SECLISTS_BASE}/Discovery/Web-Content/raft-small-directories.txt",
        f"{SECLISTS_BASE}/Discovery/Web-Content/raft-medium-directories.txt",
        f"{SECLISTS_BASE}/Discovery/Web-Content/raft-large-directories.txt",
        f"{SECLISTS_BASE}/Discovery/Web-Content/big.txt",
        f"{SECLISTS_BASE}/Discovery/Web-Content/api/api-endpoints.txt",
        f"{SECLISTS_BASE}/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt",
        f"{SECLISTS_BASE}/Discovery/Web-Content/quickhits.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    ],
    "dns": [
        f"{SECLISTS_BASE}/Discovery/DNS/subdomains-top1million-5000.txt",
        f"{SECLISTS_BASE}/Discovery/DNS/subdomains-top1million-20000.txt",
        f"{SECLISTS_BASE}/Discovery/DNS/subdomains-top1million-110000.txt",
        f"{SECLISTS_BASE}/Discovery/DNS/bitquark-subdomains-top100000.txt",
        f"{SECLISTS_BASE}/Discovery/DNS/dns-Jhaddix.txt",
        f"{SECLISTS_BASE}/Discovery/DNS/deepmagic.com-prefixes-top50000.txt",
        f"{SECLISTS_BASE}/Discovery/DNS/fierce-hostlist.txt",
    ],
    "vhost": [
        f"{SECLISTS_BASE}/Discovery/DNS/subdomains-top1million-5000.txt",
        f"{SECLISTS_BASE}/Discovery/DNS/subdomains-top1million-20000.txt",
        f"{SECLISTS_BASE}/Discovery/DNS/namelist.txt",
        f"{SECLISTS_BASE}/Discovery/DNS/deepmagic.com-prefixes-top50000.txt",
        f"{SECLISTS_BASE}/Discovery/Web-Content/common.txt",
    ],
}

FALLBACK_WORDLIST = "wordlists/common.txt"  # bundled small list, used if nothing above exists


def prompt_for_wordlist(mode: str, default_wordlist: str) -> str:
    """List real SecLists wordlists relevant to this specific gobuster mode."""
    candidates = [w for w in WORDLISTS_BY_MODE.get(mode, []) if Path(w).exists()]

    print(f"\nWordlist options for '{mode}' mode:")
    for i, w in enumerate(candidates, start=1):
        print(f"  [{i}] {w}")
    custom_idx = len(candidates) + 1
    default_idx = len(candidates) + 2
    print(f"  [{custom_idx}] Enter a custom wordlist path")
    print(f"  [{default_idx}] Use bundled default ({default_wordlist})")

    if not candidates:
        print(f"  (No SecLists wordlists found at {SECLISTS_BASE} — install with: "
              f"sudo apt install seclists, or git clone https://github.com/danielmiessler/SecLists.git)")

    choice = input(f"Choose [1-{default_idx}] (Enter = bundled default): ").strip()

    if not choice:
        return default_wordlist
    try:
        idx = int(choice)
        if 1 <= idx <= len(candidates):
            return candidates[idx - 1]
        if idx == custom_idx:
            custom = input("Enter full wordlist path: ").strip()
            return custom if custom else default_wordlist
    except ValueError:
        pass
    return default_wordlist


def prompt_for_web_enum_extras() -> dict:
    """
    Asks once (not per-mode) for the extra tuning options real gobuster/whatweb
    usage relies on: file extensions to append (dir mode only — e.g. finding
    'admin.php.bak' that a bare 'admin' wordlist entry alone won't reveal),
    thread count, whether to skip TLS certificate validation (needed for
    self-signed HTTPS targets, common in labs), and whatweb's aggression level.
    Returns a dict consumed by run_gobuster / run_whatweb; every key has a
    safe default if the user just presses Enter.
    """
    print("\n--- Gobuster/WhatWeb tuning options (press Enter for defaults) ---")
    ext = input("File extensions to try in 'dir' mode, comma-separated "
                "(e.g. php,bak,txt,zip) [default: none]: ").strip()
    threads = input("Thread count [default: gobuster's own default, 10]: ").strip()
    skip_tls = input("Skip TLS certificate validation? Needed for self-signed HTTPS "
                      "(e.g. lab targets) (y/N): ").strip().lower() == "y"
    aggression = input("WhatWeb aggression level 1-4 "
                        "(1=passive/stealthy, 3=default balanced, 4=aggressive/noisy) "
                        "[default: 1]: ").strip()

    return {
        "gobuster_extensions": ext or None,
        "gobuster_threads": int(threads) if threads.isdigit() else None,
        "gobuster_skip_tls": skip_tls,
        "whatweb_aggression": aggression if aggression in ("1", "2", "3", "4") else "1",
    }


def get_vhost_baseline_length(url: str) -> int:
    """
    gobuster's vhost mode is noisy against servers that don't actually do
    virtual-hosting: every guessed hostname gets the exact same generic
    response, so without filtering, every single wordlist entry looks like
    a "finding". This sends one request with an obviously-fake Host header
    to measure that baseline response size, so it can be excluded via
    --exclude-length — leaving only genuinely different (real) vhosts.
    Returns None if the probe fails (vhost mode then runs unfiltered).
    """
    fake_host = "reconToReport-baseline-" + "".join(random.choices(string.ascii_lowercase, k=8))
    try:
        req = urllib.request.Request(url, headers={"Host": fake_host, "User-Agent": "ReconToReport/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            return len(resp.read())
    except urllib.error.HTTPError as e:
        # Even an error response (e.g. 400/404) has a body we can measure
        try:
            return len(e.read())
        except Exception:
            return None
    except (urllib.error.URLError, TimeoutError):
        return None


def run_gobuster(url: str, outdir: Path, wordlist: str, mode: str,
                  extensions: str = None, threads: int = None, skip_tls: bool = False) -> Path:
    """
    dir/vhost modes take a full URL (-u). dns mode is different — it brute-forces
    subdomains of a DOMAIN (-d), not a URL, and is meaningless against a bare IP
    (there's no subdomain to enumerate for "192.168.1.5"). This function adapts
    the gobuster invocation per-mode instead of always passing -u.

    extensions: only meaningful for 'dir' mode (-x php,bak,...) — dns/vhost
                mode ignore it, since they enumerate names, not files.
    threads:    applies to any mode (-t N).
    skip_tls:   applies only when the target URL is https (-k).
    """
    host = url.split("//")[-1].split(":")[0].split("/")[0]
    safe_name = url.split("//")[-1].replace(":", "_").replace("/", "_")
    out_file = outdir / f"gobuster_{mode}_{safe_name}.txt"

    if mode == "dns":
        if is_ip(host):
            log.warning(f"Skipping gobuster dns mode for {host} — it's a bare IP, "
                        f"not a domain, so there are no subdomains to enumerate.")
            return None
        cmd = ["gobuster", "dns", "-d", host, "-w", wordlist, "-o", str(out_file), "-q"]
    else:
        # dir and vhost modes both operate on the full URL
        cmd = ["gobuster", mode, "-u", url, "-w", wordlist, "-o", str(out_file), "-q"]
        if mode == "dir" and extensions:
            cmd += ["-x", extensions]
        if mode == "vhost":
            baseline_len = get_vhost_baseline_length(url)
            if baseline_len is not None:
                cmd += ["--exclude-length", str(baseline_len)]
                log.info(f"vhost baseline response size for {url}: {baseline_len} bytes "
                         f"— excluding matches of this size (likely non-vhost false positives)")
            else:
                log.warning(f"Could not establish a vhost baseline for {url} — "
                             f"results may include false positives from the server's default response.")

    if threads:
        cmd += ["-t", str(threads)]
    if skip_tls and url.startswith("https"):
        cmd += ["-k"]

    log.info(f"Running: {' '.join(cmd)}")
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    except FileNotFoundError:
        log.warning("gobuster not found. Install it: sudo apt install gobuster")
        return None
    except subprocess.TimeoutExpired:
        log.warning(f"gobuster timed out for {url} (mode={mode})")
    return out_file if out_file.exists() else None


def run_gobuster_all_modes(url: str, outdir: Path, default_wordlist: str, interactive: bool = True,
                            preselected: dict = None) -> dict:
    """
    Walks through dir -> dns -> vhost, one mode at a time. For each mode:
      - interactive: ask for a wordlist (Enter = skip that mode entirely)
      - non-interactive / preselected: use whatever was pre-chosen (or skip)
    Returns {mode: {"wordlist": ..., "output_file": ...}} for every mode that ran.
    """
    results = {}
    modes = ["dir", "dns", "vhost"]
    host = url.split("//")[-1].split(":")[0].split("/")[0]

    if is_ip(host):
        log.info(f"{host} is a bare IP, not a domain — 'dns' mode (subdomain enumeration) "
                 f"doesn't apply and will be skipped automatically.")
        modes = ["dir", "vhost"]

    if preselected is not None:
        # "Apply to all targets" flow — preselected = {"dir": wordlist_or_None, ..., "extras": {...}}
        extras = preselected.get("extras", {})
        for mode in modes:
            wordlist = preselected.get(mode)
            if not wordlist:
                continue
            out_file = run_gobuster(url, outdir, wordlist, mode,
                                     extensions=extras.get("gobuster_extensions"),
                                     threads=extras.get("gobuster_threads"),
                                     skip_tls=extras.get("gobuster_skip_tls", False))
            if out_file:
                results[mode] = {"wordlist": wordlist, "output_file": str(out_file)}
        return results, extras.get("whatweb_aggression", "1")

    extras = prompt_for_web_enum_extras() if interactive else {}

    for mode in modes:
        if interactive:
            print(f"\n--- gobuster [{mode}] mode ---")
            run_it = input(f"Run gobuster in '{mode}' mode against {url}? "
                            f"Press Enter to skip, or type anything to run it: ").strip()
            if not run_it:
                log.info(f"Skipping gobuster '{mode}' mode (user skipped)")
                continue
            wordlist = prompt_for_wordlist(mode, default_wordlist)
        else:
            # Non-interactive default: only run 'dir' mode, skip dns/vhost
            if mode != "dir":
                continue
            wordlist = default_wordlist

        out_file = run_gobuster(url, outdir, wordlist, mode,
                                 extensions=extras.get("gobuster_extensions"),
                                 threads=extras.get("gobuster_threads"),
                                 skip_tls=extras.get("gobuster_skip_tls", False))
        if out_file:
            results[mode] = {"wordlist": wordlist, "output_file": str(out_file)}

    return results, extras.get("whatweb_aggression", "1")


def build_interactive_gobuster_preselection(default_wordlist: str) -> dict:
    """
    For the "apply to all targets" flow: ask once, per mode, whether to run it
    and with which wordlist, plus the shared tuning extras. Returns
    {"dir": wordlist_or_None, "dns": ..., "vhost": ..., "extras": {...}}
    which is then reused for every target/URL without re-prompting.
    """
    preselected = {}
    for mode in ["dir", "dns", "vhost"]:
        print(f"\n--- gobuster [{mode}] mode (applies to all targets) ---")
        run_it = input(f"Run '{mode}' mode on every target? Press Enter to skip, or type anything to run it: ").strip()
        preselected[mode] = prompt_for_wordlist(mode, default_wordlist) if run_it else None
    preselected["extras"] = prompt_for_web_enum_extras()
    return preselected


def run_whatweb(url: str, outdir: Path, aggression: str = "1") -> Path:
    out_file = outdir / f"whatweb_{url.split('//')[-1].replace(':', '_').replace('/', '_')}.txt"
    cmd = ["whatweb", "--color=never", "--no-errors", "-a", aggression, url]  # -a: aggression level 1-4
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
    for payload in SQLI_PAYLOADS:
        test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
        body = _fetch(test_url)
        for sig in SQL_ERROR_SIGNATURES:
            if re.search(sig, body, re.IGNORECASE):
                return {"vulnerable": True, "payload": payload, "matched_signature": sig, "param": param}
    return {"vulnerable": False, "param": param}


def probe_xss(url: str, param: str) -> dict:
    test_url = f"{url}?{param}={urllib.parse.quote(XSS_PAYLOAD)}"
    body = _fetch(test_url)
    reflected = XSS_PAYLOAD in body
    return {"vulnerable": reflected, "param": param, "payload": XSS_PAYLOAD}


def run_owasp_probes(url: str, params: list = None) -> dict:
    test_params = params or ["id", "search", "q", "page", "user"]
    sqli_results = [probe_sqli(url, p) for p in test_params]
    xss_results = [probe_xss(url, p) for p in test_params]
    return {
        "sqli_findings": [r for r in sqli_results if r["vulnerable"]],
        "xss_findings": [r for r in xss_results if r["vulnerable"]],
        "params_tested": test_params,
    }


def run_web_enum(url: str, outdir: Path, wordlist: str, screenshot: bool = False, interactive: bool = True,
                  gobuster_preselected: dict = None) -> dict:
    result = {
        "url": url,
        "gobuster_results": None,   # {mode: {wordlist, output_file}}
        "whatweb_output": None,
        "screenshot_dir": None,
        "owasp_probes": None,
    }

    result["gobuster_results"], whatweb_aggression = run_gobuster_all_modes(
        url, outdir, wordlist, interactive=interactive, preselected=gobuster_preselected
    )

    whatweb_file = run_whatweb(url, outdir, aggression=whatweb_aggression)
    if whatweb_file:
        result["whatweb_output"] = str(whatweb_file)

    if screenshot:
        shot_dir = capture_screenshot(url, outdir)
        if shot_dir:
            result["screenshot_dir"] = str(shot_dir)

    log.info(f"Running basic OWASP probes (SQLi/XSS) on {url}")
    result["owasp_probes"] = run_owasp_probes(url)

    return result