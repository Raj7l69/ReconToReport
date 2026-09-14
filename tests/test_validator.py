"""
tests/test_validator.py
Tests for utils/validator.py — the input-validation layer that stands
between user-supplied target strings and subprocess calls.
"""
from utils.validator import validate_target, validate_targets


def test_valid_ip():
    assert validate_target("10.10.10.5") == (True, "")


def test_valid_cidr():
    assert validate_target("10.10.10.0/28") == (True, "")


def test_valid_domain():
    ok, reason = validate_target("scanme.nmap.org")
    assert ok is True
    assert reason == ""


def test_valid_subdomain_multi_level():
    ok, _ = validate_target("sub.example.co.uk")
    assert ok is True


def test_rejects_empty_string():
    ok, reason = validate_target("")
    assert ok is False
    assert "empty" in reason


def test_rejects_url_scheme():
    ok, reason = validate_target("http://10.10.10.5")
    assert ok is False
    assert "URL" in reason


def test_rejects_shell_metacharacters():
    ok, reason = validate_target("; rm -rf /")
    assert ok is False


def test_rejects_garbage_string():
    ok, _ = validate_target("not a domain")
    assert ok is False


def test_validate_targets_splits_valid_and_rejected():
    targets = ["10.10.10.5", "http://bad.com", "scanme.nmap.org", ""]
    valid, rejected = validate_targets(targets)
    assert valid == ["10.10.10.5", "scanme.nmap.org"]
    assert len(rejected) == 2
    assert rejected[0][0] == "http://bad.com"