"""
utils/validator.py
Validates that a target string is a well-formed IP, CIDR range, or domain
before it's ever passed to subprocess-based tools (nmap, gobuster, etc.).
Invalid targets are rejected early with a clear error instead of failing
deep inside a tool call with a confusing message.
"""

import ipaddress
import re

# RFC-1035-ish hostname/domain pattern: labels of letters/digits/hyphens,
# dot-separated, top-level label must be alphabetic.
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)


def is_valid_ip_or_cidr(target: str) -> bool:
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False


def is_valid_domain(target: str) -> bool:
    return bool(DOMAIN_PATTERN.match(target))


def validate_target(target: str) -> tuple:
    """
    Returns (is_valid: bool, reason: str). reason is empty when valid.
    Accepts: single IP, CIDR range, or domain name. Rejects anything else
    (URLs with schemes/paths, shell metacharacters, empty strings, etc.)
    so malformed input never reaches a subprocess call downstream.
    """
    target = target.strip()

    if not target:
        return False, "empty target"

    # Reject anything that looks like a URL — this tool expects a bare host, not a URL.
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", target):
        return False, "URLs are not accepted — provide a bare IP, CIDR, or domain (e.g. '10.10.10.5', not 'http://10.10.10.5')"

    # Reject obvious shell metacharacters defensively, even though subprocess
    # calls use list-form args (not shell=True) so injection isn't directly
    # possible — this just rejects garbage input early with a clear reason.
    if re.search(r"[;&|`$(){}<>\s]", target):
        return False, "target contains invalid characters"

    if is_valid_ip_or_cidr(target):
        return True, ""

    if is_valid_domain(target):
        return True, ""

    return False, f"'{target}' is not a valid IP, CIDR range, or domain name"


def validate_targets(targets: list) -> tuple:
    """
    Validates a list of targets. Returns (valid_targets, rejected) where
    rejected is a list of (target, reason) tuples for anything invalid.
    """
    valid, rejected = [], []
    for t in targets:
        ok, reason = validate_target(t)
        if ok:
            valid.append(t)
        else:
            rejected.append((t, reason))
    return valid, rejected