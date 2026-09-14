"""
core/scanner.py
Interactive nmap scanning: asks the user how they want to scan ports
(specific port, range, common presets, or all ports), then optionally
layers on additional nmap options or a fully custom command.

Produces two outputs per scan:
  - nmap_scan.xml  -> machine-readable, used internally for parsing
  - nmap_scan.txt  -> plain nmap console output, easy for a human to read
"""

import os
import subprocess
from pathlib import Path
from utils.logger import get_logger

log = get_logger("scanner")

PORT_MENU = """
How do you want to scan ports?
  [1] Top 100 ports        (fast)
  [2] Top 1000 ports       (default — used if you press Enter)
  [3] Specific port(s)     e.g. 80,443,8080
  [4] Port range           e.g. 1-1000
  [5] All ports            (-p- , slow but exhaustive)
"""

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
    "10": (["--script", "vuln"], "NSE 'vuln' category — checks for known vulnerabilities"),
    "11": (["--script", "default"], "NSE 'default' category — safe, commonly useful scripts"),
    "12": (["--script", "safe"], "NSE 'safe' category — won't crash services or use excessive resources"),
    "13": (["--script", "auth"], "NSE 'auth' category — checks for weak/default credentials, auth bypass"),
    "14": (["--script", "discovery"], "NSE 'discovery' category — deeper service/network info gathering"),
    "15": (["--script", "exploit"], "NSE 'exploit' category — actively attempts to exploit found vulnerabilities"),
    "16": ("CUSTOM_SCRIPT", "Enter a specific NSE script name (e.g. smb-vuln-ms17-010, http-title)"),
    "17": (["-A"], "Aggressive mode — OS detection, version detection, script scanning, traceroute"),
    "18": (["--min-rate", "1000"], "Force minimum packet rate — speeds up large scans"),
    "19": (["-f"], "Fragment packets — can help evade basic packet-filtering firewalls"),
}


def prompt_for_port_selection() -> list:
    """Ask the user how to select ports. Returns the nmap port-related args."""
    print(PORT_MENU)
    choice = input("Choose an option [1-5] (Enter = default, top 1000): ").strip()

    if choice == "1":
        return ["--top-ports", "100"]
    elif choice == "3":
        ports = input("Enter specific port(s), comma-separated (e.g. 22,80,443): ").strip()
        return ["-p", ports] if ports else ["--top-ports", "1000"]
    elif choice == "4":
        prange = input("Enter port range (e.g. 1-1000): ").strip()
        return ["-p", prange] if prange else ["--top-ports", "1000"]
    elif choice == "5":
        return ["-p-"]
    else:
        # "2" or blank/invalid -> default
        return ["--top-ports", "1000"]


def prompt_for_extra_options() -> list:
    """Ask which extra nmap options (scan type, timing, NSE, etc.) to layer on top."""
    print("\nExtra nmap options (optional — base scan + port selection always applies):")
    for key, (flags, desc) in EXTRA_OPTIONS.items():
        label = "<script name>" if flags == "CUSTOM_SCRIPT" else " ".join(flags)
        print(f"  [{key}] {label:<20} {desc}")
    print("  [0] None\n")

    choice = input("Select option numbers to add (comma-separated), or press Enter for none: ").strip()
    if not choice or choice == "0":
        return []

    extra_args = []
    for part in choice.split(","):
        part = part.strip()
        if part not in EXTRA_OPTIONS:
            if part:
                log.warning(f"Ignoring unrecognized option '{part}'")
            continue

        flags = EXTRA_OPTIONS[part][0]
        if flags == "CUSTOM_SCRIPT":
            script_name = input("Enter the NSE script name (e.g. smb-vuln-ms17-010): ").strip()
            if script_name:
                extra_args.extend(["--script", script_name])
        else:
            extra_args.extend(flags)

    return extra_args


def prompt_for_custom_command() -> str:
    """Ask if the user wants to bypass all menus and type raw nmap flags directly."""
    use_custom = input("\nUse a fully custom nmap command instead of the menus above? (y/N): ").strip().lower()
    if use_custom == "y":
        return input("Enter your custom nmap flags (e.g. '-p 21-25 -sV -Pn --script vuln'): ").strip()
    return None


def prompt_for_timing_template() -> str:
    """Nmap's -T0 (paranoid/slowest, IDS evasion) through -T5 (insane/fastest)."""
    print("\nTiming template:")
    print("  [0] T0 - Paranoid   (slowest, best IDS evasion)")
    print("  [1] T1 - Sneaky")
    print("  [2] T2 - Polite     (less bandwidth/target load)")
    print("  [3] T3 - Normal     (nmap's own default)")
    print("  [4] T4 - Aggressive (default here — good for most labs/CTFs)")
    print("  [5] T5 - Insane     (fastest, may miss results / trigger alerts)")
    choice = input("Choose timing [0-5] (Enter = T4): ").strip()
    if choice in ("0", "1", "2", "3", "4", "5"):
        return f"-T{choice}"
    return "-T4"


def build_interactive_scan_args(profile: str = "quick") -> list:
    """
    Runs the full interactive flow (custom command OR port selection + extra
    options) and returns the resulting nmap argument list. Exposed separately
    from run_nmap_scan so callers (e.g. an "apply to all targets" flow in
    main.py) can run this prompt once and reuse the resulting args across
    multiple targets instead of re-prompting per target.
    """
    custom_cmd = prompt_for_custom_command()
    if custom_cmd:
        return custom_cmd.split()

    port_args = prompt_for_port_selection()
    extra = prompt_for_extra_options()
    timing = prompt_for_timing_template()
    base_speed = [timing, "-sV"] if profile == "quick" else [timing, "-sV", "-sC", "-O"]
    return base_speed + port_args + extra


def run_nmap_scan(target: str, outdir: Path, profile: str = "quick",
                   extra_args: str = None, interactive: bool = True) -> dict:
    """
    Run nmap against target. Returns {"xml": Path, "txt": Path}.

    Interactive flow (default): asks port selection -> extra options -> or a
    fully custom command that overrides everything above.

    Non-interactive: pass extra_args (skips all prompts, used both for
    scripted/--no-prompt runs and for the "apply to all targets" flow that
    reuses a single interactive session's choices across multiple targets).
    """
    xml_out = outdir / "nmap_scan.xml"
    txt_out = outdir / "nmap_scan.txt"

    if extra_args is not None:
        scan_args = extra_args.split() if isinstance(extra_args, str) else list(extra_args)
    elif interactive:
        scan_args = build_interactive_scan_args(profile)
    else:
        scan_args = ["-T4", "-sV", "--top-ports", "1000"] if profile == "quick" else ["-T4", "-p-", "-sV", "-sC", "-O"]

    cmd = ["nmap"] + scan_args + ["-oX", str(xml_out), "-oN", str(txt_out), target]

    needs_root = "-sS" in cmd or "-sU" in cmd
    if needs_root:
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        if is_root:
            log.info("Running as root — SYN/UDP scan privileges available.")
        else:
            log.warning(
                "SYN scan (-sS) or UDP scan (-sU) selected — this specific nmap command needs root. "
                "Re-running just this command with sudo (you may be prompted for your password)."
            )
            cmd = ["sudo"] + cmd  # only this one nmap call gets elevated, not the whole tool/process

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

    log.info(f"Scan complete. Human-readable output saved to: {txt_out}")
    return {"xml": xml_out, "txt": txt_out}