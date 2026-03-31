# ⬡ Advanced Port Scanner

A **GUI-based advanced port scanner** written in Python — a simplified Nmap
with a dark-terminal Tkinter interface.

---

## Features

| Feature | Description |
|---|---|
| **TCP Scan** | Full connect scan (no root required) |
| **SYN Scan** | Half-open stealth scan (requires root + Scapy) |
| **UDP Scan** | ICMP-unreachable detection via Scapy or socket fallback |
| **Banner Grabbing** | Identifies HTTP, SSH, FTP, MySQL, Redis, and 15+ services |
| **OS Fingerprinting** | TTL + TCP window heuristics (Scapy or ping fallback) |
| **Firewall Detection** | ACK scan to identify filtered vs unfiltered ports |
| **Stealth Mode** | Random port order + jitter delays |
| **Slow Scan** | Ultra-low-noise mode with long inter-probe delays |
| **Multithreading** | Configurable thread pool (up to 500 threads) |
| **Export** | JSON, TXT, CSV output to `results/` |

---

## Project Structure

```
advanced_port_scanner/
├── main.py              ← Entry point
├── gui/
│   └── interface.py     ← Tkinter GUI
├── core/
│   ├── tcp_scan.py      ← Full TCP connect scan
│   ├── syn_scan.py      ← SYN stealth scan (Scapy)
│   ├── udp_scan.py      ← UDP scan (Scapy + socket)
│   ├── banner.py        ← Banner grabbing & service detection
│   ├── os_detect.py     ← OS fingerprinting
│   ├── firewall.py      ← ACK scan / firewall detection
│   └── stealth.py       ← Jitter, rate limiting, randomisation
├── utils/
│   ├── config.py        ← Timeouts, thresholds, port map
│   ├── logger.py        ← Rotating file + console logger
│   ├── ports.py         ← Port range helpers
│   └── helpers.py       ← Validation, hostname resolution
└── output/
    └── save.py          ← TXT / JSON / CSV export
```

---

## Quick Start

```bash
# 1. Install Python 3.10+
# 2. (Optional) Install Scapy for SYN/UDP raw scans:
pip install scapy

# 3. Run
python main.py
```

> **SYN scan, raw UDP, OS fingerprinting with Scapy, and firewall detection
> all require root/Administrator privileges.**  
> Run as `sudo python main.py` on Linux/macOS.

---

## Output Format (JSON)

```json
{
  "target":           "192.168.1.1",
  "scan_type":        "TCP",
  "scan_date":        "2025-01-15T14:30:00",
  "open_ports":       [22, 80, 443],
  "closed_ports":     [],
  "filtered_ports":   [135, 445],
  "services":         {"22": "SSH", "80": "HTTP"},
  "banners":          {"22": "SSH-2.0-OpenSSH_8.9"},
  "os":               "Linux / Unix / macOS",
  "firewall_detected": true,
  "duration":         "12.4s"
}
```

---

## Ethical & Legal Notice

> **Only scan hosts you own or have explicit written permission to test.**  
> Unauthorised port scanning may be illegal in your jurisdiction.
> This tool is for educational and authorised security assessment only.

---

## Tested Environments

- Kali Linux 2024+
- Ubuntu 22.04 / 24.04
- Windows 10/11 (TCP scan only; SYN requires raw socket support)
- Python 3.10 – 3.12
