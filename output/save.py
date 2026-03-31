# output/save.py
# Persist scan results to disk in TXT, JSON, and CSV formats.
# Works correctly on Linux (including sudo), Windows, and macOS.

import csv
import json
import os
from datetime import datetime

from utils.config import OUTPUT_DIR
from utils.logger import get_logger

log = get_logger("save")


def _ensure_output_dir() -> str:
    """
    Create and return the output directory path.
    If OUTPUT_DIR is not writable (e.g. permission error under sudo),
    fall back to ~/advanced_scanner_results/.
    """
    for candidate in [OUTPUT_DIR,
                       os.path.expanduser("~/advanced_scanner_results")]:
        try:
            os.makedirs(candidate, exist_ok=True)
            # Quick write-permission test
            test = os.path.join(candidate, ".write_test")
            with open(test, "w") as f:
                f.write("ok")
            os.remove(test)
            return candidate
        except OSError:
            log.warning("Cannot write to %s, trying fallback.", candidate)
    raise OSError("No writable output directory found.")


def _base_filename(target: str, fmt: str) -> str:
    safe_target = target.replace(".", "_").replace(":", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return os.path.join(_ensure_output_dir(), f"scan_{safe_target}_{ts}.{fmt}")


# ── JSON ──────────────────────────────────────────────────────────────────────

def save_json(results: dict) -> str:
    path = _base_filename(results.get("target", "unknown"), "json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    log.info("JSON saved → %s", path)
    return path


# ── TXT ───────────────────────────────────────────────────────────────────────

def save_txt(results: dict) -> str:
    path = _base_filename(results.get("target", "unknown"), "txt")
    open_ports   = results.get("open_ports",   [])
    closed_ports = results.get("closed_ports", [])
    filt_ports   = results.get("filtered_ports", [])
    services     = results.get("services", {})
    banners      = results.get("banners", {})

    with open(path, "w", encoding="utf-8") as f:
        f.write("=" * 60 + "\n")
        f.write("       ADVANCED PORT SCANNER — SCAN REPORT\n")
        f.write("=" * 60 + "\n")
        f.write(f"Target     : {results.get('target', 'N/A')}\n")
        f.write(f"Scan Type  : {results.get('scan_type', 'N/A')}\n")
        f.write(f"Scan Date  : {results.get('scan_date', 'N/A')}\n")
        f.write(f"Duration   : {results.get('duration', 'N/A')}\n")
        f.write(f"OS Guess   : {results.get('os', 'N/A')}\n")
        f.write(f"OS Details : TTL={results.get('os_ttl','?')}  Window={results.get('os_window','?')}  Method={results.get('os_method','?')}\n")
        f.write(f"Firewall   : {'Detected' if results.get('firewall_detected') else 'Not detected'}\n")
        f.write("-" * 60 + "\n")

        f.write(f"\nOPEN PORTS ({len(open_ports)})\n")
        f.write("-" * 40 + "\n")
        for p in sorted(open_ports):
            svc = services.get(str(p), services.get(p, "Unknown"))
            ban = banners.get(str(p),  banners.get(p,  ""))
            ban_str = (ban[:55] + "…") if len(ban) > 55 else ban
            f.write(f"  {p:<7}  {svc:<20}  {ban_str}\n")

        if filt_ports:
            f.write(f"\nFILTERED PORTS ({len(filt_ports)})\n")
            f.write("-" * 40 + "\n")
            f.write("  " + ", ".join(str(p) for p in sorted(filt_ports)) + "\n")

        if closed_ports:
            f.write(f"\nCLOSED PORTS ({len(closed_ports)})\n")
            f.write("-" * 40 + "\n")
            f.write("  " + ", ".join(str(p) for p in sorted(closed_ports)) + "\n")

        f.write("\n" + "=" * 60 + "\n")

    log.info("TXT saved → %s", path)
    return path


# ── CSV ───────────────────────────────────────────────────────────────────────

def save_csv(results: dict) -> str:
    path = _base_filename(results.get("target", "unknown"), "csv")
    open_ports   = results.get("open_ports",   [])
    closed_ports = results.get("closed_ports", [])
    filt_ports   = results.get("filtered_ports", [])
    services     = results.get("services", {})
    banners      = results.get("banners", {})

    rows = []
    for p in open_ports:
        rows.append({"port": p, "state": "open",
                     "service": services.get(str(p), services.get(p, "")),
                     "banner":  banners.get(str(p),  banners.get(p,  ""))})
    for p in filt_ports:
        rows.append({"port": p, "state": "filtered", "service": "", "banner": ""})
    for p in closed_ports:
        rows.append({"port": p, "state": "closed",   "service": "", "banner": ""})
    rows.sort(key=lambda r: r["port"])

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["port", "state", "service", "banner"])
        writer.writeheader()
        writer.writerows(rows)

    log.info("CSV saved → %s", path)
    return path


# ── Convenience wrapper ───────────────────────────────────────────────────────

def save_all(results: dict) -> dict[str, str]:
    return {"json": save_json(results), "txt": save_txt(results), "csv": save_csv(results)}
