# core/banner.py
# Service banner grabbing — connects to open ports and reads the service
# identification string sent by the server.

import socket
from utils.config import BANNER_TIMEOUT, BANNER_PROBE, BANNER_MAX_BYTES
from utils.logger import get_logger

log = get_logger("banner")

# Per-port custom probes that elicit a useful response quickly
_PORT_PROBES: dict[int, bytes] = {
    21:  b"",                          # FTP sends banner on connect
    22:  b"",                          # SSH sends banner on connect
    25:  b"EHLO scanner\r\n",          # SMTP
    80:  b"HEAD / HTTP/1.0\r\n\r\n",   # HTTP
    110: b"",                          # POP3 sends banner on connect
    143: b"",                          # IMAP sends banner on connect
    443: b"HEAD / HTTP/1.0\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\n\r\n",
}


def grab_banner(host: str, port: int, timeout: float = BANNER_TIMEOUT) -> str:
    """
    Attempt to grab the service banner from *host*:*port*.
    Returns the decoded banner string, or an empty string on failure.
    """
    probe = _PORT_PROBES.get(port, BANNER_PROBE)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Some services (SSH, FTP, POP3 …) send a banner immediately on
        # connect without requiring a probe.
        if probe:
            sock.sendall(probe)

        raw = b""
        try:
            while len(raw) < BANNER_MAX_BYTES:
                chunk = sock.recv(256)
                if not chunk:
                    break
                raw += chunk
        except socket.timeout:
            pass  # We have whatever arrived so far

        sock.close()

        banner = raw.decode("utf-8", errors="replace").strip()
        banner = banner.replace("\r", "").replace("\n", " | ")
        log.debug("Banner %s:%d → %s", host, port, banner[:80])
        return banner

    except (socket.timeout, ConnectionRefusedError, OSError) as exc:
        log.debug("Banner grab failed on %s:%d — %s", host, port, exc)
        return ""


def detect_service_from_banner(banner: str, port: int) -> str:
    """
    Heuristically identify the service from a banner string.
    Falls back to the port-number lookup in utils.ports.
    """
    b = banner.lower()

    checks = [
        ("SSH",        ("ssh", "openssh")),
        ("FTP",        ("ftp", "vsftpd", "proftpd", "filezilla")),
        ("SMTP",       ("smtp", "postfix", "sendmail", "esmtp", "220 ")),
        ("HTTP",       ("http/1.", "apache", "nginx", "iis", "lighttpd")),
        ("HTTPS",      ("https",)),
        ("MySQL",      ("mysql", "mariadb")),
        ("PostgreSQL", ("postgresql", "postgres")),
        ("MongoDB",    ("mongodb", "mongo")),
        ("Redis",      ("+pong", "-err", "redis")),
        ("Telnet",     ("telnet", "login:")),
        ("POP3",       ("+ok", "pop3")),
        ("IMAP",       ("imap", "* ok")),
        ("RDP",        ("msts", "rdp")),
        ("VNC",        ("rfb",)),
        ("SNMP",       ("snmp",)),
        ("SMB",        ("smb", "samba", "netbios")),
    ]

    for service, keywords in checks:
        if any(kw in b for kw in keywords):
            return service

    # Fall back to port-number lookup
    from utils.ports import get_service_name
    return get_service_name(port)
