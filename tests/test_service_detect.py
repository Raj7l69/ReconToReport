"""
tests/test_service_detect.py
Tests for core/service_detect.py — the nmap XML parser. Uses a small
hand-written sample XML rather than a real nmap run, so tests are fast
and don't require nmap to be installed.
"""
from pathlib import Path
from core.service_detect import parse_nmap_xml

SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.41"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parses_open_ports_only(tmp_path):
    xml_file = tmp_path / "scan.xml"
    xml_file.write_text(SAMPLE_XML)

    services = parse_nmap_xml(xml_file)

    assert len(services) == 2  # port 443 is closed, should be excluded
    ports = {s["port"] for s in services}
    assert ports == {"80", "22"}


def test_extracts_product_and_version(tmp_path):
    xml_file = tmp_path / "scan.xml"
    xml_file.write_text(SAMPLE_XML)

    services = parse_nmap_xml(xml_file)
    http_service = next(s for s in services if s["port"] == "80")

    assert http_service["service"] == "http"
    assert http_service["product"] == "Apache httpd"
    assert http_service["version"] == "2.4.41"


def test_malformed_xml_returns_empty_list(tmp_path):
    xml_file = tmp_path / "bad.xml"
    xml_file.write_text("<not><valid</xml")

    services = parse_nmap_xml(xml_file)

    assert services == []


def test_no_ports_element_returns_empty_list(tmp_path):
    xml_file = tmp_path / "empty.xml"
    xml_file.write_text("<?xml version='1.0'?><nmaprun><host></host></nmaprun>")

    services = parse_nmap_xml(xml_file)

    assert services == []