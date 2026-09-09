"""
core/scanner.py
Wraps nmap to perform fast discovery scan followed by a deeper service/version scan.
"""

import subprocess
from pathlib import Path
from utils.logger import get_logger

log = get_logger("scanner")


def run_nmap_scan(target: str, outdir: Path, profile: str = "quick") -> Path:
    """
    Run nmap against target and return path to the generated XML output.

    profile:
        quick -> top 1000 ports, -T4, -sV
        full  -> all 65535 ports, -sV -sC -O, slower but thorough
    """
    xml_out = outdir / "nmap_scan.xml"

    if profile == "quick":
        cmd = ["nmap", "-T4", "-sV", "--top-ports", "1000", "-oX", str(xml_out), target]
    else:
        cmd = ["nmap", "-T4", "-p-", "-sV", "-sC", "-O", "-oX", str(xml_out), target]

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
