"""
tests/test_cve_match.py
Tests for the pure/deterministic parts of vuln/cve_match.py — the CVSS
severity mapping. NVD/searchsploit network calls aren't exercised here
(that needs live network access); this locks down the scoring logic,
which is the part most likely to silently drift if someone "simplifies"
it later.
"""
from vuln.cve_match import severity_from_cvss


def test_critical_at_9_and_above():
    assert severity_from_cvss(9.0) == "Critical"
    assert severity_from_cvss(10.0) == "Critical"


def test_high_between_7_and_9():
    assert severity_from_cvss(7.0) == "High"
    assert severity_from_cvss(8.9) == "High"


def test_medium_between_4_and_7():
    assert severity_from_cvss(4.0) == "Medium"
    assert severity_from_cvss(6.9) == "Medium"


def test_low_between_0_and_4():
    assert severity_from_cvss(0.1) == "Low"
    assert severity_from_cvss(3.9) == "Low"


def test_none_at_zero():
    assert severity_from_cvss(0.0) == "None"


def test_unknown_when_score_missing():
    assert severity_from_cvss(None) == "Unknown"