# core/syn_scan.py
# Half-open (SYN stealth) scan using Scapy raw packets.
# ⚠️  Requires root / Administrator privileges.

import random
from utils.config import SYN_TIMEOUT
from utils.logger import get_logger

log = get_logger("syn_scan")

# Scapy import is deferred so the rest of the app still loads if Scapy is
# absent — the GUI will surface a helpful message in that case.
try:
    from scapy.all import IP, TCP, sr1, conf as scapy_conf
    scapy_conf.verb = 0          # silence Scapy's own output
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    log.warning("Scapy not installed — SYN scan unavailable.")

# Interface auto-fix — corrects "Loopback Adapter" default on Windows
from utils.iface import configure_scapy_iface

_syn_last_host: str = ""   # only reconfigure when host changes


def syn_scan_port(host: str, port: int, timeout: float = SYN_TIMEOUT) -> str:
    """
    Send a single SYN packet and interpret the response.

    Returns
    -------
    'open'    – SYN-ACK received
    'closed'  – RST received
    'filtered'– no response within *timeout*
    'error'   – Scapy unavailable or permission denied
    """
    global _syn_last_host
    if not SCAPY_AVAILABLE:
        return "error"

    # Fix interface once per target host
    if host != _syn_last_host:
        configure_scapy_iface(host)
        _syn_last_host = host

    try:
        src_port = random.randint(1024, 65535)
        pkt = IP(dst=host) / TCP(sport=src_port, dport=port, flags="S")
        response = sr1(pkt, timeout=timeout, verbose=False)

        if response is None:
            log.debug("SYN %s:%d → filtered (no response)", host, port)
            return "filtered"

        tcp_layer = response.getlayer(TCP)
        if tcp_layer is None:
            return "filtered"

        flags = tcp_layer.flags

        if flags & 0x12:          # SYN-ACK  (0x02 | 0x10)
            # Send RST to cleanly close the half-open connection
            rst = IP(dst=host) / TCP(sport=src_port, dport=port, flags="R")
            sr1(rst, timeout=1, verbose=False)
            log.debug("SYN %s:%d → open", host, port)
            return "open"
        elif flags & 0x04:        # RST
            log.debug("SYN %s:%d → closed", host, port)
            return "closed"
        else:
            return "filtered"

    except PermissionError:
        log.error("SYN scan requires root/administrator privileges.")
        return "error"
    except Exception as exc:
        log.error("SYN scan error on %s:%d — %s", host, port, exc)
        return "error"
