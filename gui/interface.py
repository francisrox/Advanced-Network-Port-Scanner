# gui/interface.py
# Advanced Port Scanner — Main Tkinter GUI
# Dark terminal aesthetic with real-time output, progress tracking, and export.

import queue
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
import random
import sys
import os

# ── FIX: ensure project root is on sys.path whether run directly or via main.py
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

from utils.helpers  import validate_target, validate_port, elapsed_str
from utils.ports    import parse_port_range, get_service_name
from utils.config   import DEFAULT_THREADS, MAX_THREADS
from utils.logger   import get_logger
from core.tcp_scan  import tcp_scan_port
from core.syn_scan  import syn_scan_port, SCAPY_AVAILABLE
from core.udp_scan  import udp_scan_port
from core.banner    import grab_banner, detect_service_from_banner
from core.os_detect import detect_os
from core.firewall  import detect_firewall
from core.stealth   import randomise_ports, jitter, RateLimiter
from output.save    import save_json, save_txt, save_csv

log = get_logger("gui")

# ── Palette ────────────────────────────────────────────────────────────────────
BG_DARK   = "#0d1117"
BG_MID    = "#161b22"
BG_PANEL  = "#1c2333"
BG_INPUT  = "#0d1117"
BORDER    = "#30363d"
FG_MAIN   = "#c9d1d9"
FG_DIM    = "#6e7681"
FG_HEAD   = "#e6edf3"
COL_OPEN  = "#3fb950"   # green
COL_FILT  = "#d29922"   # yellow/amber
COL_CLOSE = "#f85149"   # red
COL_INFO  = "#58a6ff"   # blue
COL_ACCT  = "#79c0ff"   # accent blue
COL_WARN  = "#ffa657"   # orange
MONO_FONT = ("Consolas", 10)
HEAD_FONT = ("Consolas", 11, "bold")
TITLE_FONT= ("Consolas", 15, "bold")
LABEL_FONT= ("Consolas", 9)


class ScannerGUI:
    """Main application window."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Advanced Port Scanner v2.0")
        self.root.configure(bg=BG_DARK)
        self.root.minsize(1100, 700)

        # ── State ──────────────────────────────────────────────────────────
        self._scan_thread:   threading.Thread | None = None
        self._stop_event     = threading.Event()
        self._result_queue:  queue.Queue = queue.Queue()
        self._scan_results:  dict        = {}
        self._start_time:    float       = 0.0
        self._ports_total:   int         = 0
        self._ports_done:    int         = 0
        self._timer_id:      str | None  = None

        self._build_ui()
        self._poll_queue()

    # ══════════════════════════════════════════════════════════════════════════
    #  UI CONSTRUCTION
    # ══════════════════════════════════════════════════════════════════════════

    def _build_ui(self):
        self.root.columnconfigure(0, weight=0, minsize=320)
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main_panel()
        self._build_status_bar()

    # ── Sidebar ───────────────────────────────────────────────────────────────

    def _build_sidebar(self):
        sidebar = tk.Frame(self.root, bg=BG_MID, width=320,
                           highlightbackground=BORDER, highlightthickness=1)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)

        # Title
        title_frame = tk.Frame(sidebar, bg=BG_MID)
        title_frame.pack(fill="x", pady=(18, 6), padx=18)
        tk.Label(title_frame, text="⬡ PORT SCANNER",
                 font=TITLE_FONT, fg=COL_ACCT, bg=BG_MID).pack(anchor="w")
        tk.Label(title_frame, text="Advanced Network Reconnaissance",
                 font=LABEL_FONT, fg=FG_DIM, bg=BG_MID).pack(anchor="w")

        sep = tk.Frame(sidebar, bg=BORDER, height=1)
        sep.pack(fill="x", padx=12)

        form = tk.Frame(sidebar, bg=BG_MID)
        form.pack(fill="x", padx=18, pady=10)

        def _lbl(parent, text):
            tk.Label(parent, text=text, font=LABEL_FONT,
                     fg=FG_DIM, bg=BG_MID, anchor="w").pack(fill="x", pady=(8,1))

        def _entry(parent, var, placeholder=""):
            e = tk.Entry(parent, textvariable=var, font=MONO_FONT,
                         bg=BG_INPUT, fg=FG_MAIN, insertbackground=FG_MAIN,
                         relief="flat", bd=0,
                         highlightbackground=BORDER, highlightthickness=1,
                         highlightcolor=COL_ACCT)
            e.pack(fill="x", ipady=5)
            return e

        # Target
        _lbl(form, "TARGET HOST / IP")
        self.var_target = tk.StringVar(value="")
        _entry(form, self.var_target)

        # Port range
        port_row = tk.Frame(form, bg=BG_MID)
        port_row.pack(fill="x")
        port_row.columnconfigure(0, weight=1)
        port_row.columnconfigure(2, weight=1)

        pl = tk.Frame(port_row, bg=BG_MID)
        pl.grid(row=0, column=0, sticky="ew", padx=(0, 4))
        _lbl(pl, "START PORT")
        self.var_start = tk.StringVar(value="1")
        _entry(pl, self.var_start)

        tk.Label(port_row, text="–", font=("Consolas", 13),
                 fg=FG_DIM, bg=BG_MID).grid(row=0, column=1, padx=4, pady=(22,0))

        pr = tk.Frame(port_row, bg=BG_MID)
        pr.grid(row=0, column=2, sticky="ew", padx=(4, 0))
        _lbl(pr, "END PORT")
        self.var_end = tk.StringVar(value="1024")
        _entry(pr, self.var_end)

        # Scan type
        _lbl(form, "SCAN TYPE")
        self.var_scan_type = tk.StringVar(value="TCP")
        scan_types = ["TCP (Connect)", "SYN (Stealth)", "UDP"]
        type_map = {"TCP (Connect)": "TCP", "SYN (Stealth)": "SYN", "UDP": "UDP"}
        self._type_map = type_map

        type_frame = tk.Frame(form, bg=BG_MID)
        type_frame.pack(fill="x")
        for st in scan_types:
            rb = tk.Radiobutton(type_frame, text=st,
                                variable=self.var_scan_type,
                                value=type_map[st],
                                font=LABEL_FONT,
                                fg=FG_MAIN, bg=BG_MID,
                                selectcolor=BG_DARK,
                                activeforeground=COL_ACCT,
                                activebackground=BG_MID,
                                cursor="hand2")
            rb.pack(anchor="w", pady=1)

        # Threads
        _lbl(form, f"THREADS  (max {MAX_THREADS})")
        self.var_threads = tk.StringVar(value=str(DEFAULT_THREADS))
        _entry(form, self.var_threads)

        sep2 = tk.Frame(sidebar, bg=BORDER, height=1)
        sep2.pack(fill="x", padx=12, pady=(4,0))

        # ── Options ───────────────────────────────────────────────────────
        opt_frame = tk.Frame(sidebar, bg=BG_MID)
        opt_frame.pack(fill="x", padx=18, pady=8)

        tk.Label(opt_frame, text="OPTIONS", font=("Consolas", 8, "bold"),
                 fg=FG_DIM, bg=BG_MID).pack(anchor="w", pady=(4,4))

        self.var_stealth  = tk.BooleanVar(value=False)
        self.var_slow     = tk.BooleanVar(value=False)
        self.var_os       = tk.BooleanVar(value=True)
        self.var_banner   = tk.BooleanVar(value=True)
        self.var_firewall = tk.BooleanVar(value=False)

        def _chk(parent, text, var, fg=FG_MAIN, extra=""):
            f = tk.Frame(parent, bg=BG_MID)
            f.pack(anchor="w", pady=1)
            cb = tk.Checkbutton(f, text=text, variable=var,
                                font=LABEL_FONT, fg=fg, bg=BG_MID,
                                selectcolor=BG_DARK,
                                activeforeground=COL_ACCT,
                                activebackground=BG_MID,
                                cursor="hand2")
            cb.pack(side="left")
            if extra:
                tk.Label(f, text=extra, font=("Consolas", 8),
                         fg=FG_DIM, bg=BG_MID).pack(side="left", padx=4)

        _chk(opt_frame, "Stealth Mode",      self.var_stealth,  COL_FILT, "(jitter)")
        _chk(opt_frame, "Slow Scan",         self.var_slow,     COL_FILT, "(ultra)")
        _chk(opt_frame, "OS Fingerprinting", self.var_os,       COL_INFO)
        _chk(opt_frame, "Service Detection", self.var_banner,   COL_INFO)
        _chk(opt_frame, "Firewall Detection",self.var_firewall, COL_WARN, "(root)")

        sep3 = tk.Frame(sidebar, bg=BORDER, height=1)
        sep3.pack(fill="x", padx=12, pady=(4,0))

        # ── Control Buttons ───────────────────────────────────────────────
        btn_frame = tk.Frame(sidebar, bg=BG_MID)
        btn_frame.pack(fill="x", padx=18, pady=14)

        self.btn_start = tk.Button(
            btn_frame, text="▶  START SCAN",
            command=self._start_scan,
            font=("Consolas", 10, "bold"),
            bg=COL_OPEN, fg=BG_DARK,
            relief="flat", cursor="hand2",
            activebackground="#2ea043",
            activeforeground=BG_DARK,
            bd=0)
        self.btn_start.pack(fill="x", ipady=8, pady=(0, 6))

        self.btn_stop = tk.Button(
            btn_frame, text="■  STOP SCAN",
            command=self._stop_scan,
            font=("Consolas", 10, "bold"),
            bg=COL_CLOSE, fg=BG_DARK,
            relief="flat", cursor="hand2",
            activebackground="#da3633",
            activeforeground=BG_DARK,
            bd=0, state="disabled")
        self.btn_stop.pack(fill="x", ipady=8, pady=(0, 6))

        self.btn_export = tk.Button(
            btn_frame, text="↓  EXPORT RESULTS",
            command=self._export_results,
            font=("Consolas", 10, "bold"),
            bg=BG_PANEL, fg=COL_ACCT,
            relief="flat", cursor="hand2",
            activebackground=BORDER,
            activeforeground=FG_HEAD,
            highlightbackground=BORDER, highlightthickness=1,
            bd=0, state="disabled")
        self.btn_export.pack(fill="x", ipady=6)

        # ── Mini stats panel ──────────────────────────────────────────────
        sep4 = tk.Frame(sidebar, bg=BORDER, height=1)
        sep4.pack(fill="x", padx=12, pady=(4,0))

        stats = tk.Frame(sidebar, bg=BG_MID)
        stats.pack(fill="x", padx=18, pady=10)

        def _stat(parent, label, color, attr):
            row = tk.Frame(parent, bg=BG_MID)
            row.pack(fill="x", pady=1)
            tk.Label(row, text=label, font=LABEL_FONT, fg=FG_DIM,
                     bg=BG_MID, width=14, anchor="w").pack(side="left")
            lbl = tk.Label(row, text="0", font=("Consolas", 10, "bold"),
                           fg=color, bg=BG_MID, anchor="w")
            lbl.pack(side="left")
            setattr(self, attr, lbl)

        _stat(stats, "OPEN",      COL_OPEN,  "lbl_open_count")
        _stat(stats, "CLOSED",    COL_CLOSE, "lbl_closed_count")
        _stat(stats, "FILTERED",  COL_FILT,  "lbl_filt_count")
        _stat(stats, "SCANNED",   FG_MAIN,   "lbl_total_count")
        _stat(stats, "ELAPSED",   FG_DIM,    "lbl_elapsed")

    # ── Main Panel ────────────────────────────────────────────────────────────

    def _build_main_panel(self):
        panel = tk.Frame(self.root, bg=BG_DARK)
        panel.grid(row=0, column=1, sticky="nsew", padx=(1,0))
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(1, weight=1)

        # ── Header bar ────────────────────────────────────────────────────
        header = tk.Frame(panel, bg=BG_MID,
                          highlightbackground=BORDER, highlightthickness=1)
        header.grid(row=0, column=0, sticky="ew")

        tk.Label(header, text="SCAN RESULTS",
                 font=HEAD_FONT, fg=FG_HEAD, bg=BG_MID).pack(side="left", padx=16, pady=8)

        self.lbl_scan_status = tk.Label(
            header, text="● IDLE", font=("Consolas", 9, "bold"),
            fg=FG_DIM, bg=BG_MID)
        self.lbl_scan_status.pack(side="left", padx=8)

        # Clear button
        tk.Button(header, text="✕ CLEAR",
                  command=self._clear_output,
                  font=LABEL_FONT, fg=FG_DIM, bg=BG_MID,
                  relief="flat", cursor="hand2",
                  activebackground=BORDER,
                  bd=0).pack(side="right", padx=10, pady=4)

        # ── Column headers ────────────────────────────────────────────────
        col_hdr = tk.Frame(panel, bg=BG_PANEL,
                           highlightbackground=BORDER, highlightthickness=1)
        col_hdr.grid(row=1, column=0, sticky="ew")
        for txt, w in [("PORT", 8), ("STATE", 12), ("SERVICE", 18), ("BANNER / INFO", 60)]:
            tk.Label(col_hdr, text=txt, font=("Consolas", 9, "bold"),
                     fg=FG_DIM, bg=BG_PANEL,
                     width=w, anchor="w").pack(side="left", padx=(12,0), pady=4)

        # ── Scrollable output area ────────────────────────────────────────
        out_frame = tk.Frame(panel, bg=BG_DARK)
        out_frame.grid(row=2, column=0, sticky="nsew")
        panel.rowconfigure(2, weight=1)

        self.output_text = tk.Text(
            out_frame, bg=BG_DARK, fg=FG_MAIN,
            font=MONO_FONT, wrap="none",
            relief="flat", bd=0,
            selectbackground=BORDER, selectforeground=FG_HEAD,
            insertbackground=FG_MAIN, state="disabled",
            exportselection=True)

        vsb = ttk.Scrollbar(out_frame, orient="vertical",
                            command=self.output_text.yview)
        hsb = ttk.Scrollbar(out_frame, orient="horizontal",
                            command=self.output_text.xview)
        self.output_text.configure(yscrollcommand=vsb.set,
                                   xscrollcommand=hsb.set)

        self.output_text.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        out_frame.rowconfigure(0, weight=1)
        out_frame.columnconfigure(0, weight=1)

        # Tags for colour-coding
        self.output_text.tag_configure("open",    foreground=COL_OPEN)
        self.output_text.tag_configure("closed",  foreground=COL_CLOSE)
        self.output_text.tag_configure("filtered",foreground=COL_FILT)
        self.output_text.tag_configure("info",    foreground=COL_INFO)
        self.output_text.tag_configure("warn",    foreground=COL_WARN)
        self.output_text.tag_configure("head",    foreground=FG_HEAD)
        self.output_text.tag_configure("dim",     foreground=FG_DIM)
        self.output_text.tag_configure("accent",  foreground=COL_ACCT)

        # ── Progress bar ──────────────────────────────────────────────────
        prog_frame = tk.Frame(panel, bg=BG_MID,
                              highlightbackground=BORDER, highlightthickness=1)
        prog_frame.grid(row=3, column=0, sticky="ew")

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("green.Horizontal.TProgressbar",
                        troughcolor=BG_DARK, background=COL_OPEN,
                        bordercolor=BORDER, lightcolor=COL_OPEN,
                        darkcolor=COL_OPEN)

        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_bar = ttk.Progressbar(
            prog_frame, variable=self.progress_var,
            style="green.Horizontal.TProgressbar",
            maximum=100, mode="determinate")
        self.progress_bar.pack(fill="x", padx=12, pady=6)

        self.lbl_progress = tk.Label(prog_frame, text="Ready",
                                     font=LABEL_FONT, fg=FG_DIM,
                                     bg=BG_MID)
        self.lbl_progress.pack(anchor="w", padx=12, pady=(0,4))

    # ── Status bar ────────────────────────────────────────────────────────────

    def _build_status_bar(self):
        bar = tk.Frame(self.root, bg=BG_MID,
                       highlightbackground=BORDER, highlightthickness=1)
        bar.grid(row=1, column=0, columnspan=2, sticky="ew")
        self.lbl_statusbar = tk.Label(
            bar, text="Ready — configure target and press Start Scan",
            font=LABEL_FONT, fg=FG_DIM, bg=BG_MID, anchor="w")
        self.lbl_statusbar.pack(side="left", padx=12, pady=3)

        # Scapy warning
        if not SCAPY_AVAILABLE:
            tk.Label(bar, text="⚠ Scapy not installed — SYN/UDP raw scans unavailable",
                     font=LABEL_FONT, fg=COL_WARN, bg=BG_MID).pack(side="right", padx=12)

    # ══════════════════════════════════════════════════════════════════════════
    #  OUTPUT HELPERS
    # ══════════════════════════════════════════════════════════════════════════

    def _append(self, text: str, tag: str = ""):
        self.output_text.configure(state="normal")
        if tag:
            self.output_text.insert("end", text, tag)
        else:
            self.output_text.insert("end", text)
        self.output_text.see("end")
        self.output_text.configure(state="disabled")

    def _clear_output(self):
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.configure(state="disabled")
        self._scan_results = {}
        self.btn_export.configure(state="disabled")
        self._reset_stats()

    def _reset_stats(self):
        for attr, val in [("lbl_open_count","0"), ("lbl_closed_count","0"),
                          ("lbl_filt_count","0"),  ("lbl_total_count","0"),
                          ("lbl_elapsed","0s")]:
            getattr(self, attr).configure(text=val)
        self.progress_var.set(0)
        self.lbl_progress.configure(text="Ready")
        self._ports_done = 0

    def _update_status(self, text: str, color: str = FG_DIM):
        self.lbl_scan_status.configure(text=text, fg=color)
        self.lbl_statusbar.configure(text=text)

    # ══════════════════════════════════════════════════════════════════════════
    #  SCAN CONTROL
    # ══════════════════════════════════════════════════════════════════════════

    def _start_scan(self):
        # ── Validate inputs ───────────────────────────────────────────────
        ok, target = validate_target(self.var_target.get())
        if not ok:
            messagebox.showerror("Invalid Target", target)
            return

        ok_s, start_port = validate_port(self.var_start.get())
        ok_e, end_port   = validate_port(self.var_end.get())
        if not ok_s or not ok_e:
            messagebox.showerror("Invalid Ports", "Port must be 0–65535.")
            return

        try:
            threads = int(self.var_threads.get())
            threads = max(1, min(threads, MAX_THREADS))
        except ValueError:
            threads = DEFAULT_THREADS

        scan_type = self.var_scan_type.get()

        if scan_type == "SYN" and not SCAPY_AVAILABLE:
            messagebox.showwarning(
                "Scapy Required",
                "SYN scan requires Scapy.\n\nInstall with:\n  pip install scapy\n\n"
                "Falling back to TCP scan.")
            scan_type = "TCP"

        # ── Prepare ───────────────────────────────────────────────────────
        self._clear_output()
        self._stop_event.clear()
        ports = parse_port_range(start_port, end_port)

        if self.var_stealth.get():
            ports = randomise_ports(ports)

        self._ports_total = len(ports)
        self._ports_done  = 0
        self._start_time  = time.monotonic()
        self._scan_results = {
            "target":          target,
            "scan_type":       scan_type,
            "scan_date":       datetime.now().isoformat(timespec="seconds"),
            "open_ports":      [],
            "closed_ports":    [],
            "filtered_ports":  [],
            "services":        {},
            "banners":         {},
            "os":              "Unknown",
            "firewall_detected": False,
            "duration":        "0s",
        }

        # ── Update UI ─────────────────────────────────────────────────────
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.btn_export.configure(state="disabled")
        self._update_status("● RUNNING", COL_OPEN)
        self.lbl_progress.configure(text=f"Scanning {target}  ·  {len(ports)} ports  ·  {scan_type}")

        # Banner
        self._append(f"\n{'═'*70}\n", "head")
        self._append(f"  TARGET   : {target}\n", "accent")
        self._append(f"  PORTS    : {start_port} – {end_port}  ({len(ports)} ports)\n", "dim")
        self._append(f"  SCAN     : {scan_type}  ·  threads={threads}\n", "dim")
        self._append(f"  STARTED  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", "dim")
        self._append(f"{'═'*70}\n\n", "head")

        # Start elapsed timer
        self._tick_timer()

        # ── Launch worker thread ──────────────────────────────────────────
        self._scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(target, ports, scan_type, threads,
                  self.var_stealth.get(), self.var_slow.get(),
                  self.var_os.get(), self.var_banner.get(),
                  self.var_firewall.get()),
            daemon=True)
        self._scan_thread.start()

    def _stop_scan(self):
        if self._scan_thread and self._scan_thread.is_alive():
            self._stop_event.set()
            self._result_queue.put(("__STOPPED__", None))
            log.info("Scan stopped by user.")

    def _tick_timer(self):
        if self._scan_thread and self._scan_thread.is_alive():
            elapsed = time.monotonic() - self._start_time
            self.lbl_elapsed.configure(text=elapsed_str(elapsed))
            self._timer_id = self.root.after(500, self._tick_timer)
        else:
            if self._start_time:
                elapsed = time.monotonic() - self._start_time
                self.lbl_elapsed.configure(text=elapsed_str(elapsed))

    # ══════════════════════════════════════════════════════════════════════════
    #  SCAN WORKER  (runs in background thread)
    # ══════════════════════════════════════════════════════════════════════════

    def _scan_worker(self, host, ports, scan_type, max_workers,
                     stealth, slow, do_os, do_banner, do_fw):
        q    = self._result_queue
        stop = self._stop_event

        # Choose scan function
        if scan_type == "SYN":
            scan_fn = lambda h, p: syn_scan_port(h, p)
        elif scan_type == "UDP":
            scan_fn = lambda h, p: udp_scan_port(h, p)
        else:
            scan_fn = lambda h, p: tcp_scan_port(h, p)

        rate_limiter = RateLimiter(rate=max(10, max_workers * 2))

        # ── Port scanning with thread pool ────────────────────────────────
        port_queue: queue.Queue = queue.Queue()
        for p in ports:
            port_queue.put(p)

        result_lock = threading.Lock()
        open_list, closed_list, filt_list = [], [], []

        def worker():
            while not stop.is_set():
                try:
                    port = port_queue.get(timeout=0.2)
                except queue.Empty:
                    break
                if stop.is_set():
                    break

                if stealth or slow:
                    jitter(slow=slow)

                rate_limiter.acquire()
                state = scan_fn(host, port)

                # Normalise UDP "open|filtered"
                if state == "open|filtered":
                    display_state = "filtered"
                else:
                    display_state = state

                with result_lock:
                    if display_state == "open":
                        open_list.append(port)
                    elif display_state == "closed":
                        closed_list.append(port)
                    else:
                        filt_list.append(port)

                # Banner grab for open ports
                svc, banner_text = "", ""
                if display_state == "open" and do_banner:
                    banner_text = grab_banner(host, port)
                    svc = detect_service_from_banner(banner_text, port)
                elif display_state == "open":
                    svc = get_service_name(port)

                q.put(("port", {
                    "port":    port,
                    "state":   display_state,
                    "service": svc,
                    "banner":  banner_text,
                }))
                port_queue.task_done()

        threads = []
        for _ in range(min(max_workers, len(ports))):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()

        if stop.is_set():
            q.put(("__STOPPED__", None))
            return

        # ── OS fingerprinting ─────────────────────────────────────────────
        os_info = {"os_guess": "Unknown", "ttl": 0, "initial_ttl": 0, "window": 0, "method": "—"}
        if do_os:
            q.put(("info", "⟳ Running OS fingerprinting…"))
            os_info = detect_os(host, open_ports=open_list)

        # ── Firewall detection ────────────────────────────────────────────
        fw_info = {"firewall_detected": False, "filtered_ports": [],
                   "confidence": "unavailable", "note": "Not requested."}
        if do_fw:
            q.put(("info", "⟳ Running firewall detection (ACK scan)…"))
            fw_info = detect_firewall(host, sample_ports=list(open_list[:8]) + [80, 443, 22, 8080])

        # ── Send summary ──────────────────────────────────────────────────
        q.put(("done", {
            "open":     open_list,
            "closed":   closed_list,
            "filtered": filt_list,
            "os":       os_info,
            "fw":       fw_info,
        }))

    # ══════════════════════════════════════════════════════════════════════════
    #  QUEUE POLLING  (GUI thread)
    # ══════════════════════════════════════════════════════════════════════════

    def _poll_queue(self):
        try:
            while True:
                msg_type, payload = self._result_queue.get_nowait()

                if msg_type == "port":
                    self._handle_port_result(payload)

                elif msg_type == "info":
                    self._append(f"\n  {payload}\n", "info")

                elif msg_type == "__STOPPED__":
                    self._finalize_scan(stopped=True)

                elif msg_type == "done":
                    self._handle_done(payload)

        except queue.Empty:
            pass
        finally:
            self.root.after(80, self._poll_queue)

    # ── Handle individual port result ────────────────────────────────────────

    def _handle_port_result(self, data: dict):
        port    = data["port"]
        state   = data["state"]
        svc     = data.get("service", "")
        banner  = data.get("banner", "")

        self._ports_done += 1

        # Update progress
        pct = (self._ports_done / max(self._ports_total, 1)) * 100
        self.progress_var.set(pct)

        # Update counts
        open_c  = int(self.lbl_open_count.cget("text"))
        close_c = int(self.lbl_closed_count.cget("text"))
        filt_c  = int(self.lbl_filt_count.cget("text"))

        if state == "open":
            open_c += 1
            self.lbl_open_count.configure(text=str(open_c))
            self._scan_results["open_ports"].append(port)
            if svc:
                self._scan_results["services"][str(port)] = svc
            if banner:
                self._scan_results["banners"][str(port)] = banner
        elif state == "closed":
            close_c += 1
            self.lbl_closed_count.configure(text=str(close_c))
            self._scan_results["closed_ports"].append(port)
        else:
            filt_c += 1
            self.lbl_filt_count.configure(text=str(filt_c))
            self._scan_results["filtered_ports"].append(port)

        self.lbl_total_count.configure(text=str(self._ports_done))

        # Only print open / filtered to output (suppress closed for speed)
        if state == "open":
            svc_str = f"{svc:<18}" if svc else f"{'':18}"
            ban_str = (banner[:55] + "…") if len(banner) > 55 else banner
            self._append(f"  {port:<7} ", "open")
            self._append(f"{'OPEN':<12}", "open")
            self._append(f"{svc_str}  {ban_str}\n", "open")

        elif state == "filtered":
            svc_str = get_service_name(port)
            self._append(f"  {port:<7} ", "filtered")
            self._append(f"{'FILTERED':<12}", "filtered")
            self._append(f"{svc_str}\n", "filtered")

    # ── Handle scan completion ────────────────────────────────────────────────

    def _handle_done(self, payload: dict):
        elapsed = time.monotonic() - self._start_time
        dur_str = elapsed_str(elapsed)
        self._scan_results["duration"] = dur_str

        os_info = payload.get("os", {})
        fw_info = payload.get("fw", {})

        self._scan_results["os"]               = os_info.get("os_guess", "Unknown")
        self._scan_results["os_ttl"]            = os_info.get("ttl", 0)
        self._scan_results["os_window"]         = os_info.get("window", 0)
        self._scan_results["os_method"]         = os_info.get("method", "—")
        self._scan_results["firewall_detected"] = fw_info.get("firewall_detected", False)

        # Summary block
        self._append(f"\n{chr(9552)*70}\n", "head")
        self._append("  SCAN COMPLETE\n", "accent")
        self._append(f"  Duration  : {dur_str}\n", "dim")
        self._append(f"  Open      : {len(payload['open'])}\n", "open")
        self._append(f"  Filtered  : {len(payload['filtered'])}\n", "filtered")
        self._append(f"  Closed    : {len(payload['closed'])}\n", "closed")

        # OS fingerprint block — show even if TTL=0 (port-based deduction)
        os_guess = os_info.get("os_guess", "Unknown")
        if os_guess and os_guess != "Unknown":
            ttl_obs  = os_info.get("ttl", 0)
            ttl_init = os_info.get("initial_ttl", 0)
            window   = os_info.get("window", 0)
            method   = os_info.get("method", "—")
            self._append(f"\n  OS Guess  : {os_guess}\n", "info")
            if ttl_obs:
                self._append(f"  TTL obs/init: {ttl_obs} / {ttl_init}    Window: {window}\n", "dim")
            self._append(f"  Method    : {method}\n", "dim")
        else:
            self._append("\n  OS Guess  : Unknown (enable OS Detection or run as root)\n", "dim")

        # Firewall detection block
        if self.var_firewall.get():
            conf = fw_info.get("confidence", "unavailable")
            note = fw_info.get("note", "")
            if conf == "unavailable":
                self._append(f"\n  Firewall  : Detection unavailable\n", "warn")
                if note:
                    self._append(f"  Note      : {note}\n", "dim")
            else:
                fw_str = "DETECTED" if fw_info["firewall_detected"] else "Not detected"
                fw_col = "warn" if fw_info["firewall_detected"] else "dim"
                self._append(f"\n  Firewall  : {fw_str} (confidence: {conf})\n", fw_col)
                if note:
                    self._append(f"  Note      : {note}\n", "dim")
        if payload["open"]:
            self._append(f"\n  TOP OPEN PORTS :\n", "head")
            for p in sorted(payload["open"])[:20]:
                svc = self._scan_results["services"].get(str(p), get_service_name(p))
                self._append(f"    {p:<7}  {svc}\n", "open")

        self._append(f"\n{'═'*70}\n\n", "head")

        self._finalize_scan(stopped=False)

    def _finalize_scan(self, stopped: bool):
        elapsed = time.monotonic() - self._start_time
        self.lbl_elapsed.configure(text=elapsed_str(elapsed))

        if stopped:
            self._update_status("■ STOPPED", COL_CLOSE)
            self._append("\n  [!] Scan stopped by user.\n", "warn")
        else:
            self._update_status("✔ COMPLETED", COL_OPEN)

        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        if self._scan_results.get("open_ports") or self._scan_results.get("filtered_ports"):
            self.btn_export.configure(state="normal")

        self.progress_var.set(100)

    # ══════════════════════════════════════════════════════════════════════════
    #  EXPORT
    # ══════════════════════════════════════════════════════════════════════════

    def _export_results(self):
        if not self._scan_results:
            messagebox.showinfo("No Results", "Nothing to export yet.")
            return

        fmt = tk.StringVar(value="json")
        win = tk.Toplevel(self.root)
        win.title("Export Results")
        win.configure(bg=BG_MID)
        win.resizable(False, False)
        win.geometry("300x200")

        tk.Label(win, text="Choose export format:",
                 font=HEAD_FONT, fg=FG_HEAD, bg=BG_MID).pack(pady=(16,8))

        for f, label in [("json","JSON (structured)"),("txt","TXT (report)"),("csv","CSV (table)")]:
            tk.Radiobutton(win, text=label, variable=fmt, value=f,
                           font=LABEL_FONT, fg=FG_MAIN, bg=BG_MID,
                           selectcolor=BG_DARK,
                           activeforeground=COL_ACCT,
                           activebackground=BG_MID).pack(anchor="w", padx=24)

        def _do_export():
            chosen = fmt.get()
            win.destroy()
            try:
                if chosen == "json":
                    path = save_json(self._scan_results)
                elif chosen == "txt":
                    path = save_txt(self._scan_results)
                else:
                    path = save_csv(self._scan_results)
                messagebox.showinfo("Exported", f"Results saved to:\n{path}")
                self._append(f"\n  [✓] Exported → {path}\n", "info")
            except Exception as exc:
                messagebox.showerror("Export Error", str(exc))

        tk.Button(win, text="Export", command=_do_export,
                  font=("Consolas", 10, "bold"),
                  bg=COL_OPEN, fg=BG_DARK,
                  relief="flat", cursor="hand2",
                  activebackground="#2ea043",
                  activeforeground=BG_DARK,
                  bd=0).pack(pady=12, ipadx=20, ipady=5)


# ── Entry point ───────────────────────────────────────────────────────────────

def launch():
    root = tk.Tk()
    app  = ScannerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    launch()
