# core/udp_scan.py
# UDP scan with Windows interface auto-fix.

import socket
from utils.config import UDP_TIMEOUT
from utils.logger import get_logger

log = get_logger("udp_scan")

try:
    from scapy.all import IP, UDP, ICMP, sr1, conf as scapy_conf
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from utils.iface import configure_scapy_iface
_udp_last_host: str = ""


def udp_scan_port(host: str, port: int, timeout: float = UDP_TIMEOUT) -> str:
    if SCAPY_AVAILABLE:
        return _scapy_udp(host, port, timeout)
    return _socket_udp(host, port, timeout)


def _scapy_udp(host: str, port: int, timeout: float) -> str:
    global _udp_last_host
    if host != _udp_last_host:
        configure_scapy_iface(host)
        _udp_last_host = host
    try:
        pkt = IP(dst=host) / UDP(dport=port)
        resp = sr1(pkt, timeout=timeout, verbose=False)
        if resp is None:
            return "open|filtered"
        if resp.haslayer(UDP):
            return "open"
        if resp.haslayer(ICMP):
            icmp = resp.getlayer(ICMP)
            t, c = int(icmp.type), int(icmp.code)
            if t == 3 and c == 3:
                return "closed"
            if t == 3 and c in (1, 2, 9, 10, 13):
                return "filtered"
        return "open|filtered"
    except PermissionError:
        log.warning("UDP Scapy requires root — falling back to socket.")
        return _socket_udp(host, port, timeout)
    except Exception as exc:
        log.debug("UDP Scapy error on %s:%d — %s", host, port, exc)
        return _socket_udp(host, port, timeout)


def _socket_udp(host: str, port: int, timeout: float) -> str:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"\x00" * 8, (host, port))
        sock.recv(1024)
        return "open"
    except socket.timeout:
        return "open|filtered"
    except ConnectionRefusedError:
        return "closed"
    except OSError:
        return "open|filtered"
    finally:
        if sock:
            try: sock.close()
            except Exception: pass
