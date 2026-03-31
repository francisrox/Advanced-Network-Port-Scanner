# core/tcp_scan.py
# Full TCP connect scan — uses the OS three-way handshake.
# Most reliable scan type; works without root privileges.

import socket
from utils.config import TCP_TIMEOUT
from utils.logger import get_logger

log = get_logger("tcp_scan")


def tcp_scan_port(host: str, port: int, timeout: float = TCP_TIMEOUT) -> str:
    """
    Attempt a full TCP connection to *host*:*port*.

    Returns
    -------
    'open'    – connection succeeded (SYN → SYN-ACK → ACK)
    'closed'  – connection refused (RST received)
    'filtered'– timeout or other network error
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        if result == 0:
            log.debug("TCP %s:%d → open", host, port)
            return "open"
        else:
            log.debug("TCP %s:%d → closed (code %d)", host, port, result)
            return "closed"
    except socket.timeout:
        log.debug("TCP %s:%d → filtered (timeout)", host, port)
        return "filtered"
    except ConnectionRefusedError:
        return "closed"
    except OSError as exc:
        log.debug("TCP %s:%d → error: %s", host, port, exc)
        return "filtered"
    finally:
        sock.close()
