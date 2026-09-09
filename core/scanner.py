"""
core/scanner.py
Wraps nmap to perform a base discovery scan (quick or full profile), then
optionally prompts the user for common extra nmap options to layer on top.

Base profiles stay simple and sane by default. Anything beyond that —
SYN scan, ping-skip, UDP, NSE scripts, custom rate — is opt-in, either
via an interactive prompt or the --nmap-args flag for non-interactive runs.
"""

import subprocess
from pathlib import Path
from utils.logger import get_logger

log = get_logger("scanner")

# Base command per profile. These are the sane defaults — always applied.
BASE_PROFILES = {
    "quick": ["-T4", "-sV", "--top-ports", "1000"],
    "full": ["-T4", "-p-", "-sV", "-sC", "-O"],
}

# Common extra options offered in the interactive prompt.
# key -> (flag(s), description)
EXTRA_OPTIONS = {
    "1": (["-sS"], "SYN (stealth) scan — requires root, faster and quieter than default connect scan"),
    "2": (["-sT"], "TCP Connect scan — no root required, most reliable, more detectable"),
    "3": (["-sA"], "ACK scan — maps firewall rulesets, doesn't determine open/closed"),
    "4": (["-sW"], "Window scan — like ACK scan but uses TCP window field to infer open ports"),
    "5": (["-sN"], "TCP Null scan — no flags set, stealthy, evades some basic firewalls"),
    "6": (["-sF"], "TCP FIN scan — FIN flag only, similar evasion use-case to Null scan"),
    "7": (["-sX"], "TCP Xmas scan — FIN/PSH/URG flags set, another stealth variant"),
    "8": (["-Pn"], "Skip host discovery (ping) — use when target blocks ICMP/firewalls the host"),
    "9": (["-sU"], "UDP scan — slower, checks UDP ports (DNS, SNMP, etc.)"),
    "10": (["--script", "vuln"], "Run nmap's NSE 'vuln' script category — extra vulnerability checks"),
    "11": (["--script", "default"], "Run nmap's default NSE script category"),
    "12": (["-A"], "Aggressive mode — OS detection, version detection, script scanning, traceroute"),
    "13": (["--min-rate", "1000"], "Force minimum packet rate — speeds up large scans"),
    "14": (["-f"], "Fragment packets — can help evade basic packet-filtering firewalls"),
}


def prompt_for_extra_options() -> list:
    """
    Interactively ask the user which extra nmap options (if any) to layer
    on top of the base profile. Returns a flat list of extra nmap args.
    Called only when --nmap-args wasn't explicitly passed and stdin is
    interactive (so it doesn't hang in automated/CI runs).
    """
    print("\nExtra nmap options available (base scan runs regardless):")
    for key, (flags, desc) in EXTRA_OPTIONS.items():
        print(f"  [{key}] {' '.join(flags):<20} {desc}")
    print("  [0] None — run with base profile only\n")

    choice = input("Select option numbers to add (comma-separated, e.g. 1,2,4), or press Enter for none: ").strip()

    if not choice or choice == "0":
        return []

    extra_args = []
    for part in choice.split(","):
        part = part.strip()
        if part in EXTRA_OPTIONS:
            extra_args.extend(EXTRA_OPTIONS[part][0])
        elif part:
            log.warning(f"Ignoring unrecognized option '{part}'")

    return extra_args


def run_nmap_scan(target: str, outdir: Path, profile: str = "quick",
                   extra_args: str = None, interactive: bool = True) -> Path:
    """
    Run nmap against target and return path to the generated XML output.

    profile:      "quick" or "full" — selects the BASE_PROFILES command set.
    extra_args:   raw extra nmap flags as a string, e.g. "-Pn --script vuln".
                  If provided, this is used as-is and the interactive prompt
                  is skipped (non-interactive / scripted mode).
    interactive:  if True and extra_args is None, prompts the user for
                  extra options. Set False for unattended/batch runs.
    """
    xml_out = outdir / "nmap_scan.xml"

    base_args = BASE_PROFILES.get(profile, BASE_PROFILES["quick"])

    if extra_args is not None:
        extra = extra_args.split()
    elif interactive:
        extra = prompt_for_extra_options()
    else:
        extra = []

    cmd = ["nmap"] + base_args + extra + ["-oX", str(xml_out), target]

    # -sS and -sU require root privileges
    if "-sS" in cmd or "-sU" in cmd:
        log.info("SYN/UDP scan selected — nmap will need root privileges (run with sudo if it fails).")

    log.info(f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        if result.returncode != 0:
            log.warning(f"nmap exited with code {result.returncode}: {result.stderr[:300]}")
    except FileNotFoundError:
        raise RuntimeError("nmap not found. Install it: sudo apt install nmap")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"nmap scan timed out for target {target}")

    if not xml_out.exists():
        raise RuntimeError(f"nmap did not produce expected output at {xml_out}")

    return xml_out