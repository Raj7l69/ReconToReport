"""
modules/ssh_enum.py
Grabs the SSH banner/algorithms and checks for common weak configurations
(e.g. outdated protocol support) using ssh-audit if available.
"""

import subprocess
import socket
from pathlib import Path
from utils.logger import get_logger

log = get_logger("ssh_enum")


def grab_banner(target: str, port: str) -> str:
    try:
        with socket.create_connection((target, int(port)), timeout=5) as sock:
            banner = sock.recv(1024).decode(errors="ignore").strip()
            return banner
    except (socket.error, socket.timeout) as e:
        log.warning(f"SSH banner grab failed for {target}:{port}: {e}")
        return ""


def run_ssh_audit(target: str, port: str, outdir: Path) -> Path:
    out_file = outdir / f"ssh_audit_{port}.txt"
    cmd = ["ssh-audit", "-n", f"{target}:{port}"]  # -n: disable colored output (keeps the saved .txt readable)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        out_file.write_text(result.stdout)
        return out_file
    except FileNotFoundError:
        log.warning("ssh-audit not found. Install: pip install ssh-audit  (or apt install ssh-audit). Skipping.")
        return None
    except subprocess.TimeoutExpired:
        log.warning(f"ssh-audit timed out for {target}:{port}")
        return None


def run_ssh_enum(target: str, port: str, outdir: Path) -> dict:
    result = {
        "banner": grab_banner(target, port),
        "audit_output": None,
    }

    audit_file = run_ssh_audit(target, port, outdir)
    if audit_file:
        result["audit_output"] = str(audit_file)

    return result