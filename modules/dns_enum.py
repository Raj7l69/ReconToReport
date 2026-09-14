"""
modules/dns_enum.py
Basic DNS enumeration for domain-based targets: common record lookups
and a zone transfer (AXFR) attempt against each authoritative nameserver.
Requires target to be a domain name, not a bare IP.
"""

import subprocess
import ipaddress
from pathlib import Path
from utils.logger import get_logger

log = get_logger("dns_enum")

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]


def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target.split("/")[0])
        return True
    except ValueError:
        return False


def query_records(domain: str) -> dict:
    """Run `dig` for each common record type. Returns {record_type: raw_output}."""
    records = {}
    for rtype in RECORD_TYPES:
        cmd = ["dig", "+short", domain, rtype]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            records[rtype] = result.stdout.strip()
        except FileNotFoundError:
            log.warning("dig not found. Install: sudo apt install dnsutils. Skipping DNS record lookup.")
            return records
        except subprocess.TimeoutExpired:
            records[rtype] = ""
    return records


def get_nameservers(domain: str) -> list:
    cmd = ["dig", "+short", domain, "NS"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return [ns.strip().rstrip(".") for ns in result.stdout.splitlines() if ns.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []


def attempt_zone_transfer(domain: str, nameservers: list) -> dict:
    """Try AXFR against each nameserver. Almost always refused on properly configured DNS —
    a successful transfer is a significant finding worth flagging clearly."""
    results = {}
    for ns in nameservers:
        cmd = ["dig", f"@{ns}", domain, "AXFR"]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            transferred = "Transfer failed" not in result.stdout and result.stdout.strip() != ""
            results[ns] = {
                "transfer_successful": transferred,
                "output": result.stdout if transferred else "refused/failed",
            }
            if transferred:
                log.warning(f"Zone transfer SUCCEEDED against {ns} for {domain} — misconfiguration finding!")
        except (FileNotFoundError, subprocess.TimeoutExpired):
            results[ns] = {"transfer_successful": False, "output": "dig unavailable or timed out"}
    return results


def run_dns_enum(target: str, outdir: Path) -> dict:
    if is_ip(target):
        log.debug(f"{target} is an IP, skipping DNS enum (domain-only module)")
        return {"skipped": "target is an IP, not a domain"}

    log.info(f"Running DNS enumeration for {target}")
    records = query_records(target)
    nameservers = get_nameservers(target)
    zone_transfer = attempt_zone_transfer(target, nameservers) if nameservers else {}

    out_file = outdir / "dns_enum.txt"
    out_file.write_text(
        f"Records:\n{records}\n\nNameservers:\n{nameservers}\n\nZone Transfer Attempts:\n{zone_transfer}"
    )

    return {
        "records": records,
        "nameservers": nameservers,
        "zone_transfer": zone_transfer,
        "output_file": str(out_file),
    }