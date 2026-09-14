"""
core/service_detect.py
Parses nmap XML output into a normalized list of service dicts:
[{host, port, protocol, service, product, version, state}, ...]

Each service is tagged with the IP address of the host it was found on.
This matters for CIDR/multi-host scans, where a single nmap run discovers
several distinct hosts — without the "host" field, services from different
machines would be indistinguishable in downstream enumeration/reporting.
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from utils.logger import get_logger

log = get_logger("service_detect")


def parse_nmap_xml(xml_path: Path) -> list:
    services = []
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        log.error(f"Failed to parse nmap XML: {e}")
        return services

    root = tree.getroot()
    for host in root.findall("host"):
        addr_el = host.find("address")
        host_ip = addr_el.get("addr") if addr_el is not None else None

        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            service_el = port_el.find("service")
            service_name = service_el.get("name", "unknown") if service_el is not None else "unknown"
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""

            services.append({
                "host": host_ip,
                "port": port_el.get("portid"),
                "protocol": port_el.get("protocol"),
                "service": service_name,
                "product": product,
                "version": version,
                "state": "open",
            })

    distinct_hosts = len(set(s["host"] for s in services if s.get("host")))
    log.info(f"Parsed {len(services)} open service(s) across {distinct_hosts} host(s) from {xml_path}")
    return services