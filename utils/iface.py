# utils/iface.py
# Resolve the correct Scapy network interface on Windows, Linux, and macOS.
# The core problem on Windows: Scapy defaults to whatever interface has the
# lowest metric, which is often the loopback adapter ("Microsoft KM-TEST
# Loopback Adapter") rather than the real Ethernet/Wi-Fi card.
# This module forces Scapy to use the interface that actually has a route
# to the target host.

import socket
import sys
from utils.logger import get_logger

log = get_logger("iface")

_cached_iface: str | None = None   # cache after first successful resolution


def _get_best_iface_for(host: str) -> str | None:
    """
    Ask the OS which local interface it would use to reach *host*, then
    map that IP back to a Scapy interface name.
    Returns None on failure (caller falls back to Scapy default).
    """
    try:
        from scapy.all import conf as sc, get_if_list, get_if_addr
    except ImportError:
        return None

    # ── 1. Find local source IP the OS would use to reach the target ────────
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((host, 80))
            local_ip = s.getsockname()[0]
    except OSError:
        return None

    if local_ip in ("127.0.0.1", "0.0.0.0"):
        return None

    log.debug("Routing source IP for %s → %s", host, local_ip)

    # ── 2. Walk Scapy's interface list and find one whose address matches ────
    try:
        for iface in get_if_list():
            try:
                if get_if_addr(iface) == local_ip:
                    log.debug("Matched Scapy iface: %s", iface)
                    return iface
            except Exception:
                continue
    except Exception:
        pass

    # ── 3. Windows fallback: use scapy's route table ─────────────────────────
    try:
        from scapy.all import conf as sc
        # sc.route.route() returns (iface, gw, src)
        iface, _, src = sc.route.route(host)
        if iface and "loopback" not in iface.lower():
            log.debug("Route-table iface: %s (src %s)", iface, src)
            return iface
    except Exception:
        pass

    return None


def configure_scapy_iface(host: str) -> None:
    """
    Set scapy.conf.iface to the best interface for reaching *host*.
    Safe to call multiple times — result is cached after the first resolution.
    Only has an effect when Scapy is available.
    """
    global _cached_iface

    try:
        from scapy.all import conf as sc
    except ImportError:
        return

    # Always try a fresh lookup per host so multi-target scans stay correct
    iface = _get_best_iface_for(host)
    if iface:
        if sc.iface != iface:
            log.info("Setting Scapy interface → %s", iface)
            sc.iface = iface
        _cached_iface = iface
    else:
        log.debug("Could not determine best Scapy interface; using default: %s", sc.iface)
