#!/usr/bin/env python3
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
import sys
import json
import time
from pathlib import Path

from core.scanner import run_nmap_scan
from core.service_detect import parse_nmap_xml
from core.enum_trigger import trigger_enumeration
from vuln.cve_match import correlate_cves
from report.generator import generate_report
from utils.checkpoint import CheckpointManager
from utils.notifier import send_webhook_notification
from utils.logger import get_logger

log = get_logger("main")


def load_targets(args):
    """Return list of target strings from --target or --target-file."""
    targets = []
    if args.target:
        targets.append(args.target)
    if args.target_file:
        path = Path(args.target_file)
        if not path.exists():
            log.error(f"Target file not found: {args.target_file}")
            sys.exit(1)
        with open(path) as f:
            targets.extend([line.strip() for line in f if line.strip() and not line.startswith("#")])
    if not targets:
        log.error("No targets provided. Use --target or --target-file.")
        sys.exit(1)
    return targets


def run_pipeline_for_target(target, args, checkpoint: CheckpointManager):
    """Run the full recon -> enum -> vuln -> report pipeline for a single target."""
    outdir = Path(args.output_dir) / target.replace("/", "_")
    outdir.mkdir(parents=True, exist_ok=True)

    state = checkpoint.load(target)

    # Stage 1: Nmap scan
    if state.get("stage", 0) < 1:
        log.info(f"[{target}] Stage 1: Running nmap scan (profile={args.profile})")
        xml_path = run_nmap_scan(target, outdir, profile=args.profile,
                                  extra_args=args.nmap_args, interactive=not args.no_prompt)
        checkpoint.save(target, stage=1, data={"xml_path": str(xml_path)})
    else:
        xml_path = Path(state["data"]["xml_path"])
        log.info(f"[{target}] Skipping stage 1 (resumed), using cached scan")

    # Stage 2: Parse services
    services = parse_nmap_xml(xml_path)
    log.info(f"[{target}] Detected {len(services)} open service(s)")

    # Stage 3: Service-based enumeration
    if state.get("stage", 0) < 3:
        log.info(f"[{target}] Stage 3: Running service-specific enumeration")
        enum_results = trigger_enumeration(target, services, outdir, wordlist=args.wordlist,
                                            screenshot=args.screenshot)
        checkpoint.save(target, stage=3, data={"xml_path": str(xml_path), "enum_results": enum_results})
    else:
        enum_results = state["data"].get("enum_results", {})
        log.info(f"[{target}] Skipping stage 3 (resumed)")

    # Stage 4: CVE correlation + risk scoring (real NVD CVSS data)
    log.info(f"[{target}] Stage 4: Correlating services against NVD CVE database "
             f"(this can take a while — NVD is rate-limited without an API key)")
    findings = correlate_cves(services, nvd_api_key=args.nvd_api_key)

    # Stage 5: Report generation
    log.info(f"[{target}] Stage 5: Generating report")
    report_paths = generate_report(
        target=target,
        services=services,
        enum_results=enum_results,
        findings=findings,
        outdir=outdir,
        formats=args.export,
    )

    checkpoint.mark_complete(target)
    log.info(f"[{target}] Done. Report(s): {report_paths}")
    return report_paths


def main():
    parser = argparse.ArgumentParser(description="ReconToReport - Automated Recon-to-Report Pentesting Pipeline")
    parser.add_argument("--target", help="Single target IP or domain")
    parser.add_argument("--target-file", help="Path to file with one target per line")
    parser.add_argument("--profile", choices=["quick", "full"], default="quick",
                         help="Scan profile: quick (top ports) or full (all ports + aggressive)")
    parser.add_argument("--wordlist", default="wordlists/common.txt", help="Wordlist for directory brute-force")
    parser.add_argument("--output-dir", default="output", help="Base output directory")
    parser.add_argument("--export", nargs="+", choices=["pdf", "json", "md"], default=["md", "json"],
                         help="Report export formats")
    parser.add_argument("--screenshot", action="store_true", help="Capture screenshots of discovered web services")
    parser.add_argument("--resume", action="store_true", help="Resume from last checkpoint if available")
    parser.add_argument("--webhook", help="Slack/Discord webhook URL for completion notification")
    parser.add_argument("--nvd-api-key", help="NVD API key (optional — raises rate limit from 5/30s to ~50/30s)")
    parser.add_argument("--nmap-args", help="Extra raw nmap flags, e.g. '-Pn -sS --script vuln'. "
                                             "Skips the interactive options prompt when set.")
    parser.add_argument("--no-prompt", action="store_true",
                         help="Skip the interactive extra-nmap-options prompt (base profile only). "
                              "Use for unattended/scripted runs.")
    args = parser.parse_args()

    targets = load_targets(args)
    checkpoint = CheckpointManager(args.output_dir, resume=args.resume)

    start = time.time()
    all_reports = {}
    for target in targets:
        try:
            all_reports[target] = run_pipeline_for_target(target, args, checkpoint)
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
