"""
modules/smb_enum.py
Runs enum4linux-ng (or falls back to smbclient) against SMB services.
"""

import subprocess
from pathlib import Path
from utils.logger import get_logger

log = get_logger("smb_enum")


def run_smb_enum(target: str, outdir: Path) -> dict:
    out_file = outdir / "smb_enum.txt"
    cmd = ["enum4linux-ng", "-A", target]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        out_file.write_text(result.stdout)
        return {"output_file": str(out_file)}
    except FileNotFoundError:
        log.warning("enum4linux-ng not found, falling back to smbclient -L")
        try:
            cmd = ["smbclient", "-L", target, "-N"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            out_file.write_text(result.stdout)
            return {"output_file": str(out_file)}
        except FileNotFoundError:
            log.warning("smbclient not found either. Install samba-common-bin. Skipping SMB enum.")
            return {"error": "no SMB enumeration tool available"}
    except subprocess.TimeoutExpired:
        log.warning(f"SMB enum timed out for {target}")
        return {"error": "timeout"}