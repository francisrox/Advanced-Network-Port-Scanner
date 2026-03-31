# utils/config.py
# Global configuration constants for the advanced port scanner

# ── Scan Timeouts ────────────────────────────────────────────────────────────
TCP_TIMEOUT      = 1.0   # seconds per TCP connect attempt
UDP_TIMEOUT      = 2.0   # seconds per UDP probe
BANNER_TIMEOUT   = 3.0   # seconds to wait for a banner response
SYN_TIMEOUT      = 2.0   # seconds to wait for SYN-ACK

# ── Threading ────────────────────────────────────────────────────────────────
DEFAULT_THREADS  = 100   # default worker-thread count
MAX_THREADS      = 500   # hard upper limit

# ── Stealth Mode ─────────────────────────────────────────────────────────────
STEALTH_MIN_DELAY = 0.05  # minimum random delay (seconds)
STEALTH_MAX_DELAY = 0.3   # maximum random delay (seconds)
SLOW_SCAN_DELAY   = 1.5   # delay used in slow-scan / ultra-stealth mode

# ── Banner Grabbing ──────────────────────────────────────────────────────────
BANNER_PROBE      = b"HEAD / HTTP/1.0\r\n\r\n"
BANNER_MAX_BYTES  = 1024

# ── OS Fingerprinting TTL Thresholds ─────────────────────────────────────────
TTL_LINUX_MAX   = 64
TTL_WINDOWS_MAX = 128
TTL_CISCO_MAX   = 255

# ── Well-known port → service name mapping (augments socket.getservbyport) ──
COMMON_PORTS: dict[int, str] = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    67:   "DHCP",
    68:   "DHCP",
    69:   "TFTP",
    80:   "HTTP",
    110:  "POP3",
    111:  "RPC",
    119:  "NNTP",
    123:  "NTP",
    135:  "MSRPC",
    137:  "NetBIOS-NS",
    138:  "NetBIOS-DGM",
    139:  "NetBIOS-SSN",
    143:  "IMAP",
    161:  "SNMP",
    162:  "SNMP-Trap",
    179:  "BGP",
    194:  "IRC",
    389:  "LDAP",
    443:  "HTTPS",
    445:  "SMB",
    465:  "SMTPS",
    500:  "IKE",
    514:  "Syslog",
    515:  "LPD",
    587:  "SMTP-Submission",
    631:  "IPP",
    636:  "LDAPS",
    993:  "IMAPS",
    995:  "POP3S",
    1080: "SOCKS",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle-DB",
    1723: "PPTP",
    2049: "NFS",
    2181: "Zookeeper",
    2375: "Docker",
    2376: "Docker-TLS",
    3000: "Node/Grafana",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit",
    4848: "GlassFish",
    5000: "Flask/UPnP",
    5432: "PostgreSQL",
    5672: "RabbitMQ",
    5900: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6379: "Redis",
    6443: "Kubernetes-API",
    7001: "WebLogic",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8888: "Jupyter",
    9200: "Elasticsearch",
    9300: "Elasticsearch-Cluster",
    11211: "Memcached",
    15672: "RabbitMQ-Mgmt",
    27017: "MongoDB",
    27018: "MongoDB",
    50070: "Hadoop-HDFS",
}

# ── Output ────────────────────────────────────────────────────────────────────
# Use an absolute path so exports work regardless of the working directory
# (important when running as sudo on Linux where cwd may differ).
import os as _os
OUTPUT_DIR = _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "results")

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_FILE   = "scanner.log"
LOG_LEVEL  = "DEBUG"
