#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
"""
ReconToReport - Automated Recon-to-Report Pentesting Pipeline
Author: Rajendra Singh (Ra_one)

Usage:
    python3 main.py --target 192.168.1.10
    python3 main.py --target-file targets.txt --profile full
    python3 main.py --target example.com --resume
"""

import argparse
import os

try:
    import argcomplete  # enables shell tab-completion for --flags; optional
except ImportError:
    argcomplete = None
import sys
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from dotenv import load_dotenv
    load_dotenv()  # loads variables from a .env file in the current directory, if present
except ImportError:
    pass  # python-dotenv not installed — .env won't auto-load, but NVD_API_KEY env var still works

from core.scanner import run_nmap_scan, build_interactive_scan_args
from core.service_detect import parse_nmap_xml
from core.enum_trigger import trigger_enumeration
from modules.web_enum import build_interactive_gobuster_preselection
from vuln.cve_match import correlate_cves
from report.generator import generate_report
from utils.checkpoint import CheckpointManager
from utils.notifier import send_webhook_notification
from utils.validator import validate_targets
from utils.logger import configure_logging, get_logger

log = get_logger("main")

BANNER = r"""
   ____                     _____    ____                       _
  |  _ \ ___  ___ ___  _ __|_   _|__|  _ \ ___ _ __   ___  _ __| |_
  | |_) / _ \/ __/ _ \| '_ \ | |/ _ \ |_) / _ \ '_ \ / _ \| '__| __|
  |  _ <  __/ (_| (_) | | | || | (_) |  _ <  __/ |_) | (_) | |  | |_
  |_| \_\___|\___\___/|_| |_||_|\___/|_| \_\___| .__/ \___/|_|   \__|
                                                |_|
        Automated Recon -> Enumeration -> CVE Correlation -> Report
"""


def print_banner():
    print(BANNER)
    print("                              by Ra_one\n")
    print("  Not sure where to start? -h or --help will walk you through it.\n")


def load_targets(args) -> list:
    """
    Return the validated list of target strings from --target / --target-file.
    Invalid entries (malformed IP/CIDR/domain, URLs, shell metacharacters) are
    rejected here with a clear reason instead of failing deep inside a
    subprocess call later.
    """
    raw_targets = []
    if args.target:
        raw_targets.append(args.target)
    if args.target_file:
        path = Path(args.target_file)
        if not path.exists():
            log.error(f"Target file not found: {args.target_file}")
            sys.exit(1)
        with open(path) as f:
            raw_targets.extend([line.strip() for line in f if line.strip() and not line.startswith("#")])

    if not raw_targets:
        log.error("No targets provided. Use --target or --target-file.")
        sys.exit(1)

    valid, rejected = validate_targets(raw_targets)

    for target, reason in rejected:
        log.warning(f"Skipping invalid target '{target}': {reason}")

    if not valid:
        log.error("No valid targets remain after validation.")
        sys.exit(1)

    return valid


def prompt_apply_to_all(targets: list, args) -> dict:
    """
    When multiple targets are given interactively, ask once whether to reuse
    the same nmap/gobuster choices for all of them instead of re-prompting
    per target. Returns a dict of {"nmap_args": str, "gobuster_preselected": dict}
    if the user opts in, or an empty dict if they'd rather be prompted
    individually per target.
    """
    if len(targets) <= 1 or args.no_prompt or args.nmap_args:
        return {}

    choice = input(f"\n{len(targets)} targets loaded. Apply the same nmap/gobuster "
                    f"settings to all of them instead of prompting per target? (Y/n): ").strip().lower()
    if choice == "n":
        return {}

    log.info("Collecting shared settings once — these will be reused for every target.")
    scan_args = build_interactive_scan_args(args.profile)
    gobuster_preselected = build_interactive_gobuster_preselection(args.wordlist)

    return {
        "nmap_args": " ".join(scan_args),
        "gobuster_preselected": gobuster_preselected,
    }


def run_pipeline_for_host(host_ip: str, host_services: list, outdir: Path, args, shared: dict, is_interactive: bool) -> dict:
    """
    Runs enumeration -> CVE correlation -> report generation for ONE discovered
    host's services. Used both for the common case (a single-IP/domain target,
    where there's exactly one host) and for CIDR scans that discover multiple
    hosts — each host gets its own enumeration, findings, and report, keyed
    by its own IP, rather than everything being conflated under the original
    CIDR string.
    """
    host_outdir = outdir / host_ip.replace("/", "_")
    host_outdir.mkdir(parents=True, exist_ok=True)

    log.info(f"[{host_ip}] Running service-specific enumeration ({len(host_services)} service(s))")
    enum_results = trigger_enumeration(
        host_ip, host_services, host_outdir, wordlist=args.wordlist, screenshot=args.screenshot,
        interactive=is_interactive,
        gobuster_preselected=shared.get("gobuster_preselected"),
    )

    log.info(f"[{host_ip}] Correlating services against NVD CVE database")
    findings = correlate_cves(host_services, nvd_api_key=args.nvd_api_key, vulners_api_key=args.vulners_api_key)

    log.info(f"[{host_ip}] Generating report")
    report_paths = generate_report(
        target=host_ip, services=host_services, enum_results=enum_results,
        findings=findings, outdir=host_outdir, formats=args.export,
    )

    log.info(f"[{host_ip}] Done. Report(s): {report_paths}")
    return report_paths


def run_pipeline_for_target(target: str, args, checkpoint: CheckpointManager, shared: dict) -> dict:
    """
    Runs the nmap scan for a target (single IP/domain or CIDR range), then
    fans out to run_pipeline_for_host once per host nmap actually discovered.
    For a normal single-host target this is just one host; for a CIDR range
    it can be several, each getting its own subfolder/report.
    """
    outdir = Path(args.output_dir) / target.replace("/", "_")
    outdir.mkdir(parents=True, exist_ok=True)

    state = checkpoint.load(target)
    nmap_args = shared.get("nmap_args", args.nmap_args)
    is_interactive = not args.no_prompt and not shared

    # Stage 1: Nmap scan (one scan covers the whole target, including CIDR ranges)
    if state.get("stage", 0) < 1:
        log.info(f"[{target}] Stage 1: Running nmap scan (profile={args.profile})")
        scan_paths = run_nmap_scan(target, outdir, profile=args.profile,
                                    extra_args=nmap_args, interactive=is_interactive)
        xml_path = scan_paths["xml"]
        checkpoint.save(target, stage=1, data={"xml_path": str(xml_path), "txt_path": str(scan_paths["txt"])})
    else:
        xml_path = Path(state["data"]["xml_path"])
        log.info(f"[{target}] Skipping stage 1 (resumed), using cached scan")

    # Stage 2: Parse services, grouped by the actual host each one was found on
    services = parse_nmap_xml(xml_path)
    discovered_hosts = sorted({s["host"] for s in services if s.get("host")})

    if not discovered_hosts:
        log.warning(f"[{target}] No open services found on any host — nothing to enumerate or correlate.")
        checkpoint.mark_complete(target)
        return {}

    if len(discovered_hosts) > 1:
        log.info(f"[{target}] Nmap discovered {len(discovered_hosts)} live hosts in this range: "
                 f"{', '.join(discovered_hosts)} — each will get its own enumeration and report.")

    all_host_reports = {}
    for host_ip in discovered_hosts:
        host_services = [s for s in services if s.get("host") == host_ip]
        all_host_reports[host_ip] = run_pipeline_for_host(host_ip, host_services, outdir, args, shared, is_interactive)

    checkpoint.mark_complete(target)
    return all_host_reports


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="ReconToReport - Automated Recon-to-Report Pentesting Pipeline",
        epilog="""
Examples:
  Basic scan (interactive prompts for ports, gobuster modes, etc.):
      python3 main.py --target 192.168.56.101

  Full profile, screenshots, all report formats:
      python3 main.py --target 192.168.56.101 --profile full --screenshot --export md txt json html

  Multiple targets from a file:
      python3 main.py --target-file targets.txt

  Fully unattended, no prompts, 5 targets in parallel:
      python3 main.py --target-file targets.txt --no-prompt --workers 5

  Skip interactive nmap menu with your own flags:
      python3 main.py --target 192.168.56.101 --nmap-args "-Pn -sV --top-ports 1000"

  Resume an interrupted scan:
      python3 main.py --target 192.168.56.101 --resume

For authorized security testing only. See README.md / INSTALL.md for full setup instructions.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target", help="Single target IP, CIDR, or domain")
    parser.add_argument("--target-file", help="Path to file with one target per line")
    parser.add_argument("--profile", choices=["quick", "full"], default="quick",
                         help="Scan profile: quick (top ports) or full (all ports + aggressive)")
    parser.add_argument("--wordlist", default="wordlists/common.txt", help="Wordlist for directory brute-force")
    parser.add_argument("--output-dir", default="output", help="Base output directory")
    parser.add_argument("--export", nargs="+", choices=["pdf", "json", "md", "html", "txt"],
                         default=["md", "json", "txt"],
                         help="Report export formats (cve_findings.txt is always generated separately)")
    parser.add_argument("--screenshot", action="store_true", help="Capture screenshots of discovered web services")
    parser.add_argument("--resume", action="store_true", help="Resume from last checkpoint if available")
    parser.add_argument("--webhook", help="Slack/Discord webhook URL for completion notification")
    parser.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"),
                         help="NVD API key (optional — raises rate limit and lets more concurrent CVE lookups "
                              "run at once). Can also be set via .env or the NVD_API_KEY environment variable.")
    parser.add_argument("--vulners-api-key", default=os.environ.get("VULNERS_API_KEY"),
                         help="Vulners API key (optional — enriches the top CVE per service with exploit/PoC "
                              "links from 200+ sources). Can also be set via .env or VULNERS_API_KEY.")
    parser.add_argument("--nmap-args", help="Extra raw nmap flags, e.g. '-Pn -sS --script vuln'. "
                                             "Skips all interactive nmap prompts when set.")
    parser.add_argument("--no-prompt", action="store_true",
                         help="Skip all interactive prompts (nmap options, gobuster mode/wordlist, "
                              "apply-to-all) and run every target with sane defaults. For unattended/scripted runs.")
    parser.add_argument("--workers", type=int, default=3,
                         help="Max targets to scan concurrently in non-interactive mode (default: 3). "
                              "Ignored when running interactively, since prompts need one target at a time.")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show DEBUG-level output on the console")
    parser.add_argument("--quiet", "-q", action="store_true", help="Only show WARNING/ERROR on the console")
    parser.add_argument("--log-file", help="Also write full DEBUG-level logs to this file "
                                            "(default: <output-dir>/reconToReport.log)")
    if argcomplete:
        argcomplete.autocomplete(parser)
    args = parser.parse_args()

    log_level = "DEBUG" if args.verbose else ("WARNING" if args.quiet else "INFO")
    log_file = Path(args.log_file) if args.log_file else Path(args.output_dir) / "reconToReport.log"
    configure_logging(level=log_level, log_file=log_file)

    targets = load_targets(args)
    checkpoint = CheckpointManager(args.output_dir, resume=args.resume)
    shared = prompt_apply_to_all(targets, args)

    # Non-interactive execution (--no-prompt, explicit --nmap-args, or "apply to all" accepted)
    # can safely run multiple targets concurrently since no prompts are waiting on stdin.
    can_parallelize = len(targets) > 1 and (args.no_prompt or args.nmap_args or shared)

    start = time.time()
    all_reports = {}

    if can_parallelize:
        log.info(f"Running {len(targets)} targets concurrently (max {args.workers} at a time)")
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(run_pipeline_for_target, t, args, checkpoint, shared): t for t in targets}
            for future in as_completed(futures):
                target = futures[future]
                try:
                    all_reports[target] = future.result()
                except Exception as e:
                    log.error(f"[{target}] Pipeline failed: {e}")
    else:
        for target in targets:
            try:
                all_reports[target] = run_pipeline_for_target(target, args, checkpoint, shared)
            except KeyboardInterrupt:
                log.warning(f"Interrupted. Progress for {target} saved to checkpoint — rerun with --resume.")
                sys.exit(1)
            except Exception as e:
                log.error(f"[{target}] Pipeline failed: {e}")
                continue

    elapsed = round(time.time() - start, 2)
    log.info(f"All targets processed in {elapsed}s")

    if args.webhook:
        send_webhook_notification(args.webhook, targets=targets, elapsed=elapsed, reports=all_reports)


if __name__ == "__main__":
    main()