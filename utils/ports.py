# utils/ports.py
# Port-range helpers and well-known service name resolution.

import socket
from utils.config import COMMON_PORTS


def parse_port_range(start: int, end: int) -> list[int]:
    """Return a list of ports in [start, end] (inclusive, validated)."""
    start = max(0, min(start, 65535))
    end   = max(0, min(end,   65535))
    if start > end:
        start, end = end, start
    return list(range(start, end + 1))


def get_service_name(port: int, proto: str = "tcp") -> str:
    """
    Resolve a port number to a human-readable service name.
    First checks our curated COMMON_PORTS dict, then falls back to
    socket.getservbyport(), finally returns 'Unknown'.
    """
    if port in COMMON_PORTS:
        return COMMON_PORTS[port]
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return "Unknown"


def chunk_ports(ports: list[int], chunk_size: int = 1000) -> list[list[int]]:
    """Split a port list into smaller chunks for batched processing."""
    return [ports[i : i + chunk_size] for i in range(0, len(ports), chunk_size)]
