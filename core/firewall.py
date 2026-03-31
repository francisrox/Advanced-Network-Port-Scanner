# core/firewall.py
# Firewall / packet-filter detection via ACK scan.
#
# FIX 1: "MAC address to reach destination not found. Using broadcast."
#         → suppress Scapy ARP warnings; they're cosmetic on local networks
#           where the gateway handles routing.
# FIX 2: Windows interface error → configure_scapy_iface called before scan.
# FIX 3: ACK scan returns useful result table even when some ports error out.

import warnings
import logging
from utils.config import SYN_TIMEOUT
from utils.logger import get_logger

log = get_logger("firewall")

# Silence Scapy's verbose MAC/ARP warnings at the Python warnings level
warnings.filterwarnings("ignore", message=".*MAC address.*")
warnings.filterwarnings("ignore", message=".*broadcast.*")

try:
    from scapy.all import IP, TCP, sr1, conf as scapy_conf
    import logging as _logging
    # Also silence at the scapy logger level
    _logging.getLogger("scapy.runtime").setLevel(_logging.ERROR)
    _logging.getLogger("scapy.interactive").setLevel(_logging.ERROR)
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from utils.iface import configure_scapy_iface

_fw_last_host: str = ""


def ack_scan_port(host: str, port: int, timeout: float = SYN_TIMEOUT) -> str:
    """
    ACK-scan a single port.

    Returns
    -------
    'unfiltered' – RST received  (no stateful firewall)
    'filtered'   – no response   (firewall dropping the packet)
    'error'      – Scapy unavailable, wrong interface, or insufficient privs
    """
    global _fw_last_host
    if not SCAPY_AVAILABLE:
        return "error"

    if host != _fw_last_host:
        configure_scapy_iface(host)
        _fw_last_host = host

    try:
        import random
        sp   = random.randint(1024, 65535)
        pkt  = IP(dst=host) / TCP(sport=sp, dport=port, flags="A")
        resp = sr1(pkt, timeout=timeout, verbose=False)

        if resp is None:
            log.debug("ACK %s:%d → filtered (no response)", host, port)
            return "filtered"

        tcp = resp.getlayer(TCP)
        if tcp and (int(tcp.flags) & 0x04):   # RST flag set
            log.debug("ACK %s:%d → unfiltered (RST received)", host, port)
            return "unfiltered"

        return "filtered"

    except PermissionError:
        log.error("ACK scan requires root/Administrator privileges.")
        return "error"
    except Exception as exc:
        err_str = str(exc)
        # Swallow the "Interface not found" error that occurs on Windows when
        # the interface hasn't been set yet — it will be fixed on retry.
        if "not found" in err_str.lower() or "interface" in err_str.lower():
            log.debug("ACK scan iface error on %s:%d — %s (will retry)", host, port, exc)
            # Reset so next call re-configures the interface
            _fw_last_host = ""
        else:
            log.debug("ACK scan error on %s:%d — %s", host, port, exc)
        return "error"


def detect_firewall(host: str, sample_ports: list | None = None) -> dict:
    """
    Run ACK scans against a sample of ports and summarise firewall posture.

    Returns
    -------
    {
        "filtered_ports":    [...],
        "unfiltered_ports":  [...],
        "firewall_detected": bool,
        "confidence":        "high" | "medium" | "low" | "unavailable",
        "note":              str,
    }
    """
    if sample_ports is None:
        sample_ports = [22, 25, 80, 135, 139, 443, 445, 3389, 8080, 8443]

    if not SCAPY_AVAILABLE:
        return {
            "filtered_ports": [], "unfiltered_ports": [],
            "firewall_detected": False,
            "confidence": "unavailable",
            "note": "Scapy not installed — install scapy for firewall detection.",
        }

    filtered, unfiltered, errors = [], [], 0

    for port in sample_ports:
        result = ack_scan_port(host, port)
        if result == "filtered":
            filtered.append(port)
        elif result == "unfiltered":
            unfiltered.append(port)
        else:
            errors += 1

    total_valid = len(filtered) + len(unfiltered)

    if total_valid == 0:
        # All probes errored (likely interface / privilege issue)
        note = (
            "ACK scan could not complete — verify: "
            "(1) running as Administrator/root, "
            "(2) Npcap/libpcap installed, "
            "(3) correct network interface selected."
        )
        return {
            "filtered_ports": [], "unfiltered_ports": [],
            "firewall_detected": False,
            "confidence": "unavailable",
            "note": note,
        }

    filter_ratio = len(filtered) / total_valid

    if filter_ratio >= 0.7:
        confidence, fw_detected = "high",   True
    elif filter_ratio >= 0.3:
        confidence, fw_detected = "medium", True
    else:
        confidence, fw_detected = "high",   False

    note = (
        f"Probed {len(sample_ports)} ports: "
        f"{len(unfiltered)} unfiltered, {len(filtered)} filtered, {errors} errors."
    )

    return {
        "filtered_ports":   filtered,
        "unfiltered_ports": unfiltered,
        "firewall_detected": fw_detected,
        "confidence":        confidence,
        "note":              note,
    }
