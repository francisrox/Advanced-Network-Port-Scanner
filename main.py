#!/usr/bin/env python3
# main.py — Entry point for the Advanced Port Scanner.

import sys
import os
import warnings
import logging

# ── Add project root to sys.path BEFORE any local imports ────────────────────
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
# ─────────────────────────────────────────────────────────────────────────────

# Suppress Scapy's verbose ARP/MAC warnings that flood the terminal
# ("MAC address to reach destination not found. Using broadcast.")
warnings.filterwarnings("ignore", message=".*MAC address.*")
warnings.filterwarnings("ignore", message=".*broadcast.*")
warnings.filterwarnings("ignore", message=".*No libpcap.*")
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from utils.logger import get_logger
log = get_logger("main")


def check_python_version():
    if sys.version_info < (3, 9):
        print("[!] Python 3.9+ is required.")
        sys.exit(1)


def check_dependencies():
    missing = []
    try:
        import scapy  # noqa: F401
    except ImportError:
        missing.append("scapy")
    if missing:
        print(f"[!] Optional packages not installed: {', '.join(missing)}")
        print("    SYN / raw-UDP / OS-fingerprint / firewall detection unavailable.")
        print(f"    Install:  pip install {' '.join(missing)}\n")


def check_platform():
    """Print Windows-specific prerequisite warnings."""
    try:
        from utils.wincheck import check_and_warn
        for w in check_and_warn():
            print(f"[!] {w}\n")
    except Exception:
        pass


def main():
    check_python_version()
    check_dependencies()
    check_platform()
    log.info("Starting Advanced Port Scanner GUI…")
    try:
        from gui.interface import launch
        launch()
    except KeyboardInterrupt:
        log.info("Interrupted by user.")
    except Exception as exc:
        log.exception("Fatal error: %s", exc)
        print(f"\n[!] Fatal error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
