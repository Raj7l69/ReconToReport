"""
modules/ftp_enum.py
Checks for FTP anonymous login and grabs the service banner.
"""

import ftplib
import socket
from pathlib import Path
from utils.logger import get_logger

log = get_logger("ftp_enum")


def run_ftp_enum(target: str, port: str, outdir: Path) -> dict:
    result = {"anonymous_login": False, "banner": None}

    try:
        ftp = ftplib.FTP()
        ftp.connect(target, int(port), timeout=10)
        result["banner"] = ftp.getwelcome()

        try:
            ftp.login()  # anonymous
            result["anonymous_login"] = True
            result["directory_listing"] = ftp.nlst()
        except ftplib.error_perm:
            result["anonymous_login"] = False
        finally:
            ftp.quit()

    except (socket.error, ftplib.all_errors) as e:
        log.warning(f"FTP enum failed for {target}:{port}: {e}")
        result["error"] = str(e)

    out_file = outdir / f"ftp_enum_{port}.txt"
    out_file.write_text(str(result))
    result["output_file"] = str(out_file)
    return result
