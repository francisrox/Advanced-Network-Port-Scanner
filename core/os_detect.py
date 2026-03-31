# core/os_detect.py
# OS fingerprinting — TTL + TCP window size + service-based deduction.
#
# KEY FIX: TTL is decremented by each router hop in transit.
# A Windows host (initial TTL=128) that is 5 hops away arrives with TTL=123.
# Simple threshold checks (<=64 = Linux, <=128 = Windows) misclassify this.
#
# Solution: infer the *initial* TTL by rounding the observed value UP to the
# nearest standard starting TTL (32, 64, 128, 255), then classify from that.

import random
from utils.logger import get_logger

log = get_logger("os_detect")

try:
    from scapy.all import IP, TCP, ICMP, sr1, conf as scapy_conf
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from utils.iface import configure_scapy_iface

# Standard initial TTL values used by each OS family
_TTL_ORIGINS = [32, 64, 128, 255]


def _infer_initial_ttl(observed_ttl: int) -> int:
    """
    Round an observed (decremented) TTL up to the nearest standard origin.
    e.g. observed=123 → initial=128 (Windows)
         observed=61  → initial=64  (Linux)
         observed=250 → initial=255 (Cisco/Solaris)
    """
    for origin in _TTL_ORIGINS:
        if observed_ttl <= origin:
            return origin
    return 255


def _initial_ttl_to_os(initial_ttl: int) -> str:
    mapping = {
        32:  "Windows 9x / older device",
        64:  "Linux / Unix / macOS / Android",
        128: "Windows (NT/XP/7/10/11/Server)",
        255: "Cisco IOS / Solaris / network device",
    }
    return mapping.get(initial_ttl, "Unknown")


def _window_to_os(window: int) -> str:
    """
    TCP receive window size is a strong OS indicator.
    These are well-documented initial window sizes.
    """
    windows_sizes  = {8192, 16384, 65535}      # Windows XP/7/10/11/Server
    linux_sizes    = {5840, 14600, 29200, 65535, 32768, 87380}
    macos_sizes    = {65535, 32768, 131072}
    cisco_sizes    = {4128}

    if window in cisco_sizes:
        return "Cisco IOS"
    if window in windows_sizes and window not in linux_sizes:
        return "Windows"
    if window in linux_sizes and window not in windows_sizes:
        return "Linux"
    if window in macos_sizes and window not in linux_sizes:
        return "macOS"
    return ""


def _merge_guess(ttl_os: str, window_os: str, open_ports: list) -> str:
    """
    Combine TTL-based, window-based, and port-based evidence into one
    confident guess. Port-based evidence (135/445 = Windows) is definitive.
    """
    # Port-based fingerprinting is the most reliable
    if 135 in open_ports or 445 in open_ports or 3389 in open_ports:
        return "Windows"
    if 22 in open_ports and 80 not in open_ports and 135 not in open_ports:
        # SSH without RDP/MSRPC is a strong Linux indicator
        pass  # fall through to TTL/window

    # Both signals agree → high confidence
    if window_os and ttl_os != "Unknown":
        w_lower = window_os.lower()
        t_lower = ttl_os.lower()
        if w_lower in t_lower or any(w_lower in t for t in t_lower.split("/")):
            return ttl_os    # agree, return the more detailed string

        # They disagree — window is usually more reliable than TTL
        return f"{window_os} (TTL suggests: {ttl_os})"

    if ttl_os != "Unknown":
        return ttl_os
    if window_os:
        return window_os
    return "Unknown"


def _scapy_fingerprint(host: str, open_ports: list | None = None) -> dict:
    """
    Send ICMP + TCP SYN probes, collect TTL and window, infer OS.
    """
    if open_ports is None:
        open_ports = []

    result = {
        "ttl": 0, "initial_ttl": 0, "window": 0,
        "os_guess": "Unknown", "method": "scapy",
    }

    # Fix the Scapy interface (critical on Windows)
    configure_scapy_iface(host)

    # ── ICMP echo ────────────────────────────────────────────────────────────
    try:
        pkt  = IP(dst=host) / ICMP()
        resp = sr1(pkt, timeout=2, verbose=False)
        if resp and resp.haslayer(IP):
            result["ttl"] = int(resp[IP].ttl)
            log.debug("ICMP TTL from %s = %d", host, result["ttl"])
    except Exception as exc:
        log.debug("ICMP probe failed: %s", exc)

    # ── TCP SYN — prefer open ports we already know about ────────────────────
    probe_ports = list(open_ports) + [80, 443, 22, 135, 445, 8080, 3389]
    for probe_port in probe_ports[:8]:        # try up to 8 candidates
        try:
            sp   = random.randint(1024, 65535)
            pkt  = IP(dst=host) / TCP(sport=sp, dport=probe_port, flags="S")
            resp = sr1(pkt, timeout=2, verbose=False)
            if resp and resp.haslayer(TCP):
                result["window"] = int(resp[TCP].window)
                if result["ttl"] == 0 and resp.haslayer(IP):
                    result["ttl"] = int(resp[IP].ttl)
                    log.debug("TCP TTL from %s:%d = %d", host, probe_port, result["ttl"])
                break
        except Exception:
            continue

    # ── Derive OS guess ───────────────────────────────────────────────────────
    if result["ttl"] > 0:
        result["initial_ttl"] = _infer_initial_ttl(result["ttl"])
        ttl_os = _initial_ttl_to_os(result["initial_ttl"])
    else:
        ttl_os = "Unknown"

    window_os = _window_to_os(result["window"])
    result["os_guess"] = _merge_guess(ttl_os, window_os, open_ports)

    log.info(
        "OS fingerprint %s: TTL=%d(→%d) window=%d → %s",
        host, result["ttl"], result.get("initial_ttl", 0),
        result["window"], result["os_guess"]
    )
    return result


def _ping_fingerprint(host: str, open_ports: list | None = None) -> dict:
    """Fallback: use system ping to get TTL."""
    import subprocess, re, platform
    if open_ports is None:
        open_ports = []

    system = platform.system().lower()
    if "windows" in system:
        cmd = ["ping", "-n", "1", host]
        pat = re.compile(r"TTL[=\s]+(\d+)", re.IGNORECASE)
    else:
        cmd = ["ping", "-c", "1", "-W", "2", host]
        pat = re.compile(r"ttl=(\d+)", re.IGNORECASE)

    ttl = 0
    try:
        out = subprocess.check_output(cmd, timeout=5, stderr=subprocess.DEVNULL, text=True)
        m = pat.search(out)
        if m:
            ttl = int(m.group(1))
    except Exception:
        pass

    initial = _infer_initial_ttl(ttl) if ttl else 0
    ttl_os  = _initial_ttl_to_os(initial) if initial else "Unknown"
    guess   = _merge_guess(ttl_os, "", open_ports)

    return {
        "ttl": ttl, "initial_ttl": initial,
        "window": 0, "os_guess": guess, "method": "ping-ttl",
    }


def detect_os(host: str, open_ports: list | None = None) -> dict:
    """
    Fingerprint the OS of *host*.

    Parameters
    ----------
    host        : target IP/hostname
    open_ports  : list of already-discovered open ports (improves accuracy)

    Returns dict with: os_guess, ttl, initial_ttl, window, method
    """
    if open_ports is None:
        open_ports = []

    if SCAPY_AVAILABLE:
        try:
            return _scapy_fingerprint(host, open_ports)
        except PermissionError:
            log.warning("OS detect Scapy path needs root — using ping fallback.")

    return _ping_fingerprint(host, open_ports)
