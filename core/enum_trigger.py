"""
core/enum_trigger.py
Looks at the detected services and dispatches to the right enumeration module.
Also runs domain-level DNS enumeration once per target (not per-port) when the
target is a domain rather than a bare IP.
"""

from pathlib import Path
from utils.logger import get_logger
from modules.web_enum import run_web_enum
from modules.smb_enum import run_smb_enum
from modules.ftp_enum import run_ftp_enum
from modules.ssh_enum import run_ssh_enum
from modules.dns_enum import run_dns_enum, is_ip

log = get_logger("enum_trigger")

HTTP_SERVICES = {"http", "https", "http-proxy", "http-alt"}
SMB_SERVICES = {"microsoft-ds", "netbios-ssn", "smb"}
FTP_SERVICES = {"ftp"}
SSH_SERVICES = {"ssh"}


def trigger_enumeration(target: str, services: list, outdir: Path, wordlist: str,
                         screenshot: bool = False, interactive: bool = True,
                         gobuster_preselected: dict = None) -> dict:
    """
    Dispatch to service-specific enumeration modules based on detected services.
    Returns a dict keyed by port -> enum module output, plus a top-level "dns"
    key when the target is a domain.
    """
    results = {}

    # Domain-level DNS enum runs once per target, not per open port
    if not is_ip(target):
        try:
            results["dns"] = run_dns_enum(target, outdir)
        except Exception as e:
            log.warning(f"[{target}] DNS enum failed: {e}")
            results["dns"] = {"error": str(e)}

    for svc in services:
        name = svc.get("service", "").lower()
        port = svc.get("port")

        try:
            if name in HTTP_SERVICES:
                scheme = "https" if "https" in name or port == "443" else "http"
                url = f"{scheme}://{target}:{port}"
                log.info(f"[{target}:{port}] HTTP service detected -> running web enum on {url}")
                results[port] = run_web_enum(url, outdir, wordlist=wordlist, screenshot=screenshot,
                                              interactive=interactive, gobuster_preselected=gobuster_preselected)

            elif name in SMB_SERVICES:
                log.info(f"[{target}:{port}] SMB service detected -> running SMB enum")
                results[port] = run_smb_enum(target, outdir)

            elif name in FTP_SERVICES:
                log.info(f"[{target}:{port}] FTP service detected -> running FTP enum")
                results[port] = run_ftp_enum(target, port, outdir)

            elif name in SSH_SERVICES:
                log.info(f"[{target}:{port}] SSH service detected -> running SSH enum")
                results[port] = run_ssh_enum(target, port, outdir)

            else:
                log.debug(f"[{target}:{port}] No enum module for service '{name}', skipping")

        except Exception as e:
            log.warning(f"[{target}:{port}] Enum module failed: {e}")
            results[port] = {"error": str(e)}

    return results