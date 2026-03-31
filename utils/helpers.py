# utils/helpers.py
# Miscellaneous helper utilities used across the scanner.

import re
import socket
import ipaddress
from datetime import datetime


def resolve_host(target: str) -> str | None:
    """
    Resolve a hostname to an IPv4 address string.
    Returns None if resolution fails.
    """
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def is_valid_ip(address: str) -> bool:
    """Return True if *address* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def is_valid_hostname(hostname: str) -> bool:
    """Basic RFC-compliant hostname validation."""
    if not hostname or len(hostname) > 253:
        return False
    allowed = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")
    return all(allowed.match(part) for part in hostname.rstrip(".").split("."))


def validate_target(target: str) -> tuple[bool, str]:
    """
    Validate and resolve *target*.
    Returns (is_valid, resolved_ip_or_error_message).
    """
    target = target.strip()
    if not target:
        return False, "Target cannot be empty."

    if is_valid_ip(target):
        return True, target

    resolved = resolve_host(target)
    if resolved:
        return True, resolved

    return False, f"Cannot resolve '{target}' to an IP address."


def validate_port(value: str) -> tuple[bool, int]:
    """
    Validate a port string.
    Returns (is_valid, port_int).
    """
    try:
        port = int(value)
        if 0 <= port <= 65535:
            return True, port
        return False, -1
    except (ValueError, TypeError):
        return False, -1


def timestamp() -> str:
    """Return a filesystem-safe timestamp string: YYYYMMDD_HHMMSS."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def elapsed_str(seconds: float) -> str:
    """Format elapsed seconds as 'Xm Ys' or 'X.Xs'."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    mins = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{mins}m {secs}s"
