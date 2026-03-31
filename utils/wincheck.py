# utils/wincheck.py
# Windows-specific startup checks:
#   1. Verify Npcap/WinPcap is installed (required for Scapy raw packets)
#   2. Verify the process is running as Administrator

import sys
import platform
from utils.logger import get_logger

log = get_logger("wincheck")


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def is_admin() -> bool:
    """Return True if the current process has admin/root privileges."""
    try:
        if is_windows():
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            import os
            return os.geteuid() == 0
    except Exception:
        return False


def npcap_installed() -> bool:
    """
    Check whether Npcap (or WinPcap) is installed on Windows.
    Looks for the Npcap service and DLL in the standard locations.
    """
    if not is_windows():
        return True   # libpcap handled by the OS on Linux/macOS

    import os
    # Npcap installs here by default
    npcap_paths = [
        r"C:\Windows\System32\Npcap\wpcap.dll",
        r"C:\Windows\System32\wpcap.dll",         # WinPcap legacy
        r"C:\Windows\SysWOW64\Npcap\wpcap.dll",
    ]
    return any(os.path.isfile(p) for p in npcap_paths)


def check_and_warn() -> list[str]:
    """
    Run all Windows-specific checks and return a list of warning strings.
    Empty list = everything is fine.
    """
    warnings = []

    if not is_windows():
        if not is_admin():
            warnings.append(
                "Not running as root — SYN scan, OS detection, and firewall "
                "detection require:  sudo python main.py"
            )
        return warnings

    # ── Windows-specific ──────────────────────────────────────────────────
    if not is_admin():
        warnings.append(
            "Not running as Administrator — right-click CMD / Terminal and "
            "choose 'Run as administrator', then re-launch."
        )

    if not npcap_installed():
        warnings.append(
            "Npcap is NOT installed — Scapy cannot send/receive raw packets "
            "on Windows without it.\n"
            "  Download from: https://npcap.com/#download\n"
            "  Install with the 'WinPcap API-compatible mode' checkbox ticked."
        )

    return warnings
