"""
gui.py - SOC Event Log Extractor — Main GUI
Dark-terminal aesthetic. Tkinter-based. Fully threaded.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import threading
import datetime
import os
import sys
from typing import List, Dict, Optional

from log_reader import EventLogReader, LOG_SOURCES, SECURITY_EVENT_TAGS
from parser import EventParser, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM
from filter_engine import FilterEngine, FilterPreset, BUILTIN_PRESETS
from exporter import Exporter


# ── Palette ────────────────────────────────────────────────────────────────
C = {
    "bg":          "#0d1117",
    "bg2":         "#161b22",
    "bg3":         "#21262d",
    "border":      "#30363d",
    "text":        "#e6edf3",
    "text_dim":    "#8b949e",
    "accent":      "#58a6ff",
    "accent2":     "#3fb950",
    "warning":     "#d29922",
    "error":       "#f85149",
    "critical":    "#ff7b72",
    "purple":      "#bc8cff",
    "cyan":        "#79c0ff",
    "green":       "#3fb950",

    # Row colours (bg, fg)
    "row_critical": ("#3d1a1a", "#ff7b72"),
    "row_high":     ("#2d2012", "#e3b341"),
    "row_medium":   ("#1f2614", "#7ee787"),
    "row_info":     ("#0d1117", "#c9d1d9"),
    "row_success":  ("#0d2219", "#3fb950"),
    "row_alt":      ("#161b22", "#c9d1d9"),
}

FONT_MONO  = ("Consolas", 9)
FONT_LABEL = ("Segoe UI", 9)
FONT_BOLD  = ("Segoe UI", 9, "bold")
FONT_TITLE = ("Segoe UI", 13, "bold")

PAGE_SIZE = 200          # rows per page in the table


class SOCExtractorApp:
    """Main application window."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("⬛ Windows Event Log Extractor  —  SOC Analysis Tool")
        self.root.geometry("1440x860")
        self.root.minsize(1100, 650)
        self.root.configure(bg=C["bg"])

        self._all_events:      List[Dict] = []
        self._filtered_events: List[Dict] = []
        self._page = 0
        self._sort_col    = "TimeCreated"
        self._sort_rev    = True
        self._loading     = False
        self._load_thread: Optional[threading.Thread] = None

        self._reader  = EventLogReader(progress_cb=self._on_progress)
        self._parser  = EventParser()
        self._filter  = FilterEngine()
        self._exporter = Exporter()

        self._apply_ttk_theme()
        self._build_ui()
        self._populate_preset_menu()

    # ── Theme ───────────────────────────────────────────────────────────────

    def _apply_ttk_theme(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")

        style.configure(".",
            background=C["bg"], foreground=C["text"],
            fieldbackground=C["bg2"], troughcolor=C["bg3"],
            selectbackground=C["accent"], selectforeground=C["bg"],
            insertcolor=C["text"], font=FONT_LABEL,
        )
        style.configure("TFrame",    background=C["bg"])
        style.configure("TLabelframe", background=C["bg"], foreground=C["text_dim"],
                        bordercolor=C["border"])
        style.configure("TLabelframe.Label", background=C["bg"], foreground=C["accent"],
                        font=FONT_BOLD)
        style.configure("TLabel",  background=C["bg"],  foreground=C["text"])
        style.configure("TEntry",  fieldbackground=C["bg2"], foreground=C["text"],
                        bordercolor=C["border"], insertcolor=C["text"])
        style.configure("TCombobox", fieldbackground=C["bg2"], foreground=C["text"],
                        selectbackground=C["bg3"], arrowcolor=C["accent"])
        style.map("TCombobox", fieldbackground=[("readonly", C["bg2"])])

        # Buttons
        style.configure("TButton", background=C["bg3"], foreground=C["text"],
                        bordercolor=C["border"], relief="flat", padding=(8, 4))
        style.map("TButton",
            background=[("active", C["accent"]), ("pressed", C["accent2"])],
            foreground=[("active", C["bg"])],
        )
        style.configure("Accent.TButton", background=C["accent"], foreground=C["bg"],
                        font=FONT_BOLD)
        style.map("Accent.TButton",
            background=[("active", C["cyan"])],
        )
        style.configure("Danger.TButton", background=C["error"], foreground=C["bg"],
                        font=FONT_BOLD)
        style.configure("Success.TButton", background=C["green"], foreground=C["bg"],
                        font=FONT_BOLD)

        # Treeview
        style.configure("Treeview",
            background=C["bg"], foreground=C["text"],
            fieldbackground=C["bg"],
            rowheight=22, bordercolor=C["border"],
            font=FONT_MONO,
        )
        style.configure("Treeview.Heading",
            background=C["bg3"], foreground=C["accent"],
            font=FONT_BOLD, relief="flat",
            bordercolor=C["border"],
        )
        style.map("Treeview",
            background=[("selected", C["accent"])],
            foreground=[("selected", C["bg"])],
        )
        style.map("Treeview.Heading",
            background=[("active", C["bg2"])],
        )

        # Checkbutton
        style.configure("TCheckbutton", background=C["bg"], foreground=C["text"])
        style.map("TCheckbutton",
            background=[("active", C["bg"])],
            indicatorcolor=[("selected", C["accent"]), ("!selected", C["bg3"])],
        )

        # Notebook
        style.configure("TNotebook", background=C["bg"], bordercolor=C["border"])
        style.configure("TNotebook.Tab", background=C["bg3"], foreground=C["text_dim"],
                        padding=(10, 4))
        style.map("TNotebook.Tab",
            background=[("selected", C["bg"]), ("active", C["bg2"])],
            foreground=[("selected", C["accent"])],
        )

        # Progressbar
        style.configure("Horizontal.TProgressbar", troughcolor=C["bg2"],
                        background=C["accent"], bordercolor=C["border"])
        style.configure("TSeparator", background=C["border"])

        # Scrollbar
        style.configure("TScrollbar", background=C["bg3"], troughcolor=C["bg2"],
                        arrowcolor=C["text_dim"], bordercolor=C["border"])

    # ── UI Construction ─────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Title bar ──────────────────────────────────────────────────────
        title_bar = tk.Frame(self.root, bg=C["bg2"], pady=6)
        title_bar.pack(fill=tk.X)
        tk.Label(title_bar, text="⬛  WINDOWS EVENT LOG EXTRACTOR",
                 bg=C["bg2"], fg=C["accent"], font=("Consolas", 13, "bold")).pack(side=tk.LEFT, padx=16)
        tk.Label(title_bar, text="SOC Analysis & Incident Investigation",
                 bg=C["bg2"], fg=C["text_dim"], font=FONT_LABEL).pack(side=tk.LEFT, padx=4)

        # version / platform badge
        plat = "Windows" if sys.platform == "win32" else "Demo Mode"
        badge_col = C["accent2"] if sys.platform == "win32" else C["warning"]
        tk.Label(title_bar, text=f" {plat} ", bg=badge_col, fg=C["bg"],
                 font=FONT_BOLD).pack(side=tk.RIGHT, padx=16)

        # ── Main pane: left controls + right table ─────────────────────────
        main_pane = tk.PanedWindow(self.root, orient=tk.HORIZONTAL,
                                   bg=C["bg"], sashwidth=4,
                                   sashrelief=tk.FLAT, sashpad=2)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=0, pady=0)

        left_panel = self._build_left_panel(main_pane)
        right_panel = self._build_right_panel(main_pane)
        main_pane.add(left_panel, minsize=320, width=340)
        main_pane.add(right_panel, minsize=600)

        # ── Status bar ─────────────────────────────────────────────────────
        self._build_status_bar()

    # ── Left panel ──────────────────────────────────────────────────────────

    def _build_left_panel(self, parent) -> tk.Frame:
        frame = tk.Frame(parent, bg=C["bg2"], bd=0)

        inner = tk.Frame(frame, bg=C["bg2"])
        inner.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # ── Source section ─────────────────────────────────────────────────
        src_frame = ttk.LabelFrame(inner, text="▸ LOG SOURCE", padding=8)
        src_frame.pack(fill=tk.X, pady=(0, 8))

        tk.Label(src_frame, text="Log Type:", bg=C["bg"], fg=C["text_dim"],
                 font=FONT_LABEL).grid(row=0, column=0, sticky=tk.W, pady=2)
        self._log_var = tk.StringVar(value="Security")
        log_cb = ttk.Combobox(src_frame, textvariable=self._log_var,
                              values=LOG_SOURCES, state="readonly", width=18)
        log_cb.grid(row=0, column=1, padx=6, pady=2, sticky=tk.EW)

        tk.Label(src_frame, text="Max Records:", bg=C["bg"], fg=C["text_dim"],
                 font=FONT_LABEL).grid(row=1, column=0, sticky=tk.W, pady=2)
        self._max_var = tk.StringVar(value="5000")
        ttk.Entry(src_frame, textvariable=self._max_var, width=10).grid(
            row=1, column=1, padx=6, pady=2, sticky=tk.W)

        evtx_row = tk.Frame(src_frame, bg=C["bg"])
        evtx_row.grid(row=2, column=0, columnspan=2, pady=(4,0), sticky=tk.EW)
        ttk.Button(evtx_row, text="📂  Import EVTX File", command=self._import_evtx
                   ).pack(fill=tk.X)

        src_frame.columnconfigure(1, weight=1)

        # ── Filter section ─────────────────────────────────────────────────
        filt_frame = ttk.LabelFrame(inner, text="▸ FILTERS", padding=8)
        filt_frame.pack(fill=tk.X, pady=(0, 8))

        def lbl(parent, text, row, col=0):
            tk.Label(parent, text=text, bg=C["bg"], fg=C["text_dim"],
                     font=FONT_LABEL).grid(row=row, column=col, sticky=tk.W, pady=2)

        lbl(filt_frame, "Event ID(s):", 0)
        self._id_var = tk.StringVar()
        ttk.Entry(filt_frame, textvariable=self._id_var).grid(
            row=0, column=1, padx=6, pady=2, sticky=tk.EW)
        tk.Label(filt_frame, text="(comma-separated)", bg=C["bg"], fg=C["text_dim"],
                 font=("Segoe UI", 7)).grid(row=1, column=1, sticky=tk.W, padx=6)

        lbl(filt_frame, "Keyword:", 2)
        self._kw_var = tk.StringVar()
        ttk.Entry(filt_frame, textvariable=self._kw_var).grid(
            row=2, column=1, padx=6, pady=2, sticky=tk.EW)

        lbl(filt_frame, "Start Date/Time:", 3)
        self._start_var = tk.StringVar()
        ttk.Entry(filt_frame, textvariable=self._start_var,
                  ).grid(row=3, column=1, padx=6, pady=2, sticky=tk.EW)
        tk.Label(filt_frame, text="YYYY-MM-DD HH:MM:SS", bg=C["bg"],
                 fg=C["text_dim"], font=("Segoe UI", 7)
                 ).grid(row=4, column=1, sticky=tk.W, padx=6)

        lbl(filt_frame, "End Date/Time:", 5)
        self._end_var = tk.StringVar()
        ttk.Entry(filt_frame, textvariable=self._end_var).grid(
            row=5, column=1, padx=6, pady=2, sticky=tk.EW)

        # Time shortcuts
        shortcuts = tk.Frame(filt_frame, bg=C["bg"])
        shortcuts.grid(row=6, column=0, columnspan=2, pady=4, sticky=tk.EW)
        for label, hours in [("1h", 1), ("6h", 6), ("24h", 24), ("7d", 168)]:
            ttk.Button(shortcuts, text=label, width=4,
                       command=lambda h=hours: self._set_time_range(h)
                       ).pack(side=tk.LEFT, padx=2)
        ttk.Button(shortcuts, text="Clear", width=5,
                   command=self._clear_time_range).pack(side=tk.LEFT, padx=2)

        # Checkbox filters
        ck_frame = tk.Frame(filt_frame, bg=C["bg"])
        ck_frame.grid(row=7, column=0, columnspan=2, pady=(6,0), sticky=tk.EW)

        self._err_var  = tk.BooleanVar()
        self._warn_var = tk.BooleanVar()
        self._succ_var = tk.BooleanVar()
        self._fail_var = tk.BooleanVar()

        ttk.Checkbutton(ck_frame, text="Errors",         variable=self._err_var ).grid(row=0, column=0, sticky=tk.W)
        ttk.Checkbutton(ck_frame, text="Warnings",       variable=self._warn_var).grid(row=0, column=1, sticky=tk.W)
        ttk.Checkbutton(ck_frame, text="Audit Success",  variable=self._succ_var).grid(row=1, column=0, sticky=tk.W)
        ttk.Checkbutton(ck_frame, text="Audit Failure",  variable=self._fail_var).grid(row=1, column=1, sticky=tk.W)

        filt_frame.columnconfigure(1, weight=1)

        # ── Preset section ─────────────────────────────────────────────────
        pre_frame = ttk.LabelFrame(inner, text="▸ FILTER PRESETS", padding=8)
        pre_frame.pack(fill=tk.X, pady=(0, 8))

        self._preset_var = tk.StringVar(value="— select preset —")
        self._preset_cb = ttk.Combobox(pre_frame, textvariable=self._preset_var,
                                       state="readonly")
        self._preset_cb.pack(fill=tk.X, pady=(0, 4))
        self._preset_cb.bind("<<ComboboxSelected>>", self._apply_preset)

        btn_row = tk.Frame(pre_frame, bg=C["bg"])
        btn_row.pack(fill=tk.X)
        ttk.Button(btn_row, text="Save",   command=self._save_preset,   width=8).pack(side=tk.LEFT, padx=2)
        ttk.Button(btn_row, text="Delete", command=self._delete_preset,  width=8).pack(side=tk.LEFT, padx=2)

        # ── Action buttons ─────────────────────────────────────────────────
        act_frame = tk.Frame(inner, bg=C["bg2"])
        act_frame.pack(fill=tk.X, pady=(4, 0))

        ttk.Button(act_frame, text="⚡  LOAD LOGS", style="Accent.TButton",
                   command=self._load_logs).pack(fill=tk.X, pady=2)
        ttk.Button(act_frame, text="🔍  FILTER", style="TButton",
                   command=self._apply_filter).pack(fill=tk.X, pady=2)
        ttk.Button(act_frame, text="⟳  CLEAR FILTERS", command=self._clear_filters,
                   ).pack(fill=tk.X, pady=2)
        ttk.Button(act_frame, text="■  STOP", style="Danger.TButton",
                   command=self._stop_loading).pack(fill=tk.X, pady=2)

        sep = tk.Frame(act_frame, bg=C["border"], height=1)
        sep.pack(fill=tk.X, pady=6)

        ttk.Button(act_frame, text="💾  EXPORT", style="Success.TButton",
                   command=self._export).pack(fill=tk.X, pady=2)

        # ── Known Event IDs quick reference ───────────────────────────────
        ref_frame = ttk.LabelFrame(inner, text="▸ EVENT ID REFERENCE", padding=6)
        ref_frame.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

        ref_scroll = tk.Scrollbar(ref_frame)
        ref_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        ref_list = tk.Listbox(ref_frame, yscrollcommand=ref_scroll.set,
                              bg=C["bg"], fg=C["text_dim"], font=("Consolas", 8),
                              selectbackground=C["accent"], selectforeground=C["bg"],
                              borderwidth=0, highlightthickness=0,
                              activestyle="none")
        ref_list.pack(fill=tk.BOTH, expand=True)
        ref_scroll.config(command=ref_list.yview)

        for eid in sorted(SECURITY_EVENT_TAGS):
            tag = SECURITY_EVENT_TAGS[eid]
            ref_list.insert(tk.END, f"  {eid:5d}  {tag}")

        def ref_click(event):
            sel = ref_list.curselection()
            if sel:
                item = ref_list.get(sel[0]).strip()
                eid_str = item.split()[0]
                current = self._id_var.get().strip()
                if current:
                    self._id_var.set(current + "," + eid_str)
                else:
                    self._id_var.set(eid_str)

        ref_list.bind("<Double-1>", ref_click)
        tk.Label(ref_frame, text="Double-click to add to Event ID filter",
                 bg=C["bg"], fg=C["text_dim"], font=("Segoe UI", 7)).pack()

        return frame

    # ── Right panel: search bar + table + detail ────────────────────────────

    def _build_right_panel(self, parent) -> tk.Frame:
        frame = tk.Frame(parent, bg=C["bg"])

        # ── Search bar ──────────────────────────────────────────────────────
        search_bar = tk.Frame(frame, bg=C["bg2"], pady=5)
        search_bar.pack(fill=tk.X)
        tk.Label(search_bar, text="  🔎 ", bg=C["bg2"], fg=C["accent"],
                 font=("Segoe UI", 11)).pack(side=tk.LEFT)
        self._qs_var = tk.StringVar()
        self._qs_var.trace_add("write", lambda *_: self._quick_filter())
        qs_entry = ttk.Entry(search_bar, textvariable=self._qs_var, font=FONT_MONO)
        qs_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        tk.Label(search_bar, text="Quick search across all visible columns",
                 bg=C["bg2"], fg=C["text_dim"], font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=6)

        # Stats row
        self._stats_var = tk.StringVar(value="No events loaded")
        tk.Label(search_bar, textvariable=self._stats_var, bg=C["bg2"],
                 fg=C["text_dim"], font=FONT_LABEL).pack(side=tk.RIGHT, padx=12)

        # ── Notebook: Table + Detail ─────────────────────────────────────
        nb = ttk.Notebook(frame)
        nb.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        table_tab = tk.Frame(nb, bg=C["bg"])
        detail_tab = tk.Frame(nb, bg=C["bg"])
        nb.add(table_tab, text="  Event Table  ")
        nb.add(detail_tab, text="  Event Detail  ")

        self._nb = nb
        self._build_table(table_tab)
        self._build_detail(detail_tab)

        # ── Pagination bar ──────────────────────────────────────────────────
        pag_bar = tk.Frame(frame, bg=C["bg2"], pady=4)
        pag_bar.pack(fill=tk.X)

        ttk.Button(pag_bar, text="◀◀ First", command=self._page_first
                   ).pack(side=tk.LEFT, padx=4)
        ttk.Button(pag_bar, text="◀ Prev", command=self._page_prev
                   ).pack(side=tk.LEFT, padx=2)

        self._page_var = tk.StringVar(value="Page 1 / 1")
        tk.Label(pag_bar, textvariable=self._page_var, bg=C["bg2"],
                 fg=C["accent"], font=FONT_BOLD).pack(side=tk.LEFT, padx=10)

        ttk.Button(pag_bar, text="Next ▶", command=self._page_next
                   ).pack(side=tk.LEFT, padx=2)
        ttk.Button(pag_bar, text="Last ▶▶", command=self._page_last
                   ).pack(side=tk.LEFT, padx=4)

        tk.Label(pag_bar, text=f"({PAGE_SIZE} rows/page)", bg=C["bg2"],
                 fg=C["text_dim"], font=("Segoe UI", 8)).pack(side=tk.LEFT, padx=4)

        # Real-time refresh
        self._refresh_var = tk.BooleanVar(value=False)
        self._refresh_interval_var = tk.StringVar(value="30")
        ttk.Checkbutton(pag_bar, text="Auto-refresh every",
                        variable=self._refresh_var,
                        command=self._toggle_refresh).pack(side=tk.RIGHT, padx=4)
        ttk.Entry(pag_bar, textvariable=self._refresh_interval_var,
                  width=4).pack(side=tk.RIGHT, padx=2)
        tk.Label(pag_bar, text="sec ", bg=C["bg2"], fg=C["text_dim"],
                 font=FONT_LABEL).pack(side=tk.RIGHT)

        return frame

    def _build_table(self, parent):
        COLUMNS = [
            ("TimeCreated",  160, tk.W),
            ("EventID",       60, tk.CENTER),
            ("Level",         90, tk.CENTER),
            ("Severity",      70, tk.CENTER),
            ("Tag",          160, tk.W),
            ("Computer",     120, tk.W),
            ("User",         130, tk.W),
            ("Source",       140, tk.W),
            ("ShortMessage", 340, tk.W),
        ]

        # Container with scrollbars
        container = tk.Frame(parent, bg=C["bg"])
        container.pack(fill=tk.BOTH, expand=True)

        vsb = ttk.Scrollbar(container, orient=tk.VERTICAL)
        hsb = ttk.Scrollbar(container, orient=tk.HORIZONTAL)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        hsb.pack(side=tk.BOTTOM, fill=tk.X)

        self._tree = ttk.Treeview(
            container,
            columns=[c[0] for c in COLUMNS],
            show="headings",
            selectmode="extended",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
        )
        vsb.config(command=self._tree.yview)
        hsb.config(command=self._tree.xview)

        for col, width, anchor in COLUMNS:
            self._tree.heading(col, text=col,
                               command=lambda c=col: self._sort_by(c))
            self._tree.column(col, width=width, anchor=anchor, minwidth=40)

        self._tree.pack(fill=tk.BOTH, expand=True)

        # Row tags for colour coding
        self._tree.tag_configure("CRITICAL", background=C["row_critical"][0], foreground=C["row_critical"][1])
        self._tree.tag_configure("HIGH",     background=C["row_high"][0],     foreground=C["row_high"][1])
        self._tree.tag_configure("MEDIUM",   background=C["row_medium"][0],   foreground=C["row_medium"][1])
        self._tree.tag_configure("INFO",     background=C["row_info"][0],     foreground=C["row_info"][1])
        self._tree.tag_configure("SUCCESS",  background=C["row_success"][0],  foreground=C["row_success"][1])
        self._tree.tag_configure("ALT",      background=C["row_alt"][0],      foreground=C["row_alt"][1])

        self._tree.bind("<<TreeviewSelect>>", self._on_row_select)
        self._tree.bind("<Double-1>",         self._on_row_double)

        # Context menu
        self._ctx_menu = tk.Menu(self.root, tearoff=0, bg=C["bg2"], fg=C["text"],
                                 activebackground=C["accent"], activeforeground=C["bg"])
        self._ctx_menu.add_command(label="Copy Row",     command=self._copy_row)
        self._ctx_menu.add_command(label="Copy Message", command=self._copy_message)
        self._ctx_menu.add_separator()
        self._ctx_menu.add_command(label="Filter by this Event ID",  command=self._filter_by_id)
        self._ctx_menu.add_command(label="Filter by this Computer",  command=self._filter_by_computer)
        self._ctx_menu.add_command(label="Filter by this User",      command=self._filter_by_user)
        self._tree.bind("<Button-3>", self._show_ctx)

    def _build_detail(self, parent):
        detail_frame = tk.Frame(parent, bg=C["bg"])
        detail_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # Header area
        hdr = tk.Frame(detail_frame, bg=C["bg3"], pady=6, padx=10)
        hdr.pack(fill=tk.X, pady=(0, 6))

        self._det_id  = tk.Label(hdr, text="", bg=C["bg3"], fg=C["accent"],   font=("Consolas", 18, "bold"))
        self._det_tag = tk.Label(hdr, text="", bg=C["bg3"], fg=C["text"],     font=("Segoe UI", 10))
        self._det_sev = tk.Label(hdr, text="", bg=C["bg3"], fg=C["warning"],  font=FONT_BOLD)
        self._det_id.pack(side=tk.LEFT)
        self._det_tag.pack(side=tk.LEFT, padx=12)
        self._det_sev.pack(side=tk.RIGHT)

        # Meta grid
        meta = tk.Frame(detail_frame, bg=C["bg2"])
        meta.pack(fill=tk.X, pady=(0, 6))

        self._det_fields: Dict[str, tk.StringVar] = {}
        meta_cols = [
            ("Time", "TimeCreated"), ("Level", "Level"),
            ("Computer", "Computer"), ("User", "User"),
            ("Source", "Source"),    ("Log", "LogName"),
            ("Process", "Image"),    ("CommandLine", "CommandLine"),
            ("Source IP", "SourceIP"), ("Logon Type", "LogonType"),
            ("Service", "ServiceName"), ("Task", "TaskName"),
        ]
        for i, (label, key) in enumerate(meta_cols):
            r, c = divmod(i, 2)
            tk.Label(meta, text=f"{label}:", bg=C["bg2"], fg=C["text_dim"],
                     font=FONT_LABEL, width=12, anchor=tk.E).grid(row=r, column=c*2, sticky=tk.E, padx=(8,2), pady=2)
            var = tk.StringVar()
            self._det_fields[key] = var
            tk.Label(meta, textvariable=var, bg=C["bg2"], fg=C["text"],
                     font=FONT_MONO, anchor=tk.W).grid(row=r, column=c*2+1, sticky=tk.W, padx=(0,20), pady=2)

        # Full message text area
        tk.Label(detail_frame, text="Full Message:", bg=C["bg"], fg=C["text_dim"],
                 font=FONT_BOLD).pack(anchor=tk.W)

        msg_frame = tk.Frame(detail_frame, bg=C["bg"])
        msg_frame.pack(fill=tk.BOTH, expand=True)

        msg_vsb = ttk.Scrollbar(msg_frame)
        msg_vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self._det_text = tk.Text(msg_frame, bg=C["bg2"], fg=C["text"],
                                 font=FONT_MONO, wrap=tk.WORD,
                                 yscrollcommand=msg_vsb.set,
                                 borderwidth=0, highlightthickness=0,
                                 state=tk.DISABLED)
        self._det_text.pack(fill=tk.BOTH, expand=True)
        msg_vsb.config(command=self._det_text.yview)

    def _build_status_bar(self):
        sb = tk.Frame(self.root, bg=C["bg3"], pady=3)
        sb.pack(fill=tk.X, side=tk.BOTTOM)

        self._status_var = tk.StringVar(value="Ready.")
        tk.Label(sb, textvariable=self._status_var, bg=C["bg3"],
                 fg=C["text_dim"], font=FONT_LABEL).pack(side=tk.LEFT, padx=10)

        self._prog = ttk.Progressbar(sb, orient=tk.HORIZONTAL,
                                      mode="determinate", length=200)
        self._prog.pack(side=tk.RIGHT, padx=10)
        self._prog["value"] = 0

    # ── Load / Filter / Export ──────────────────────────────────────────────

    def _load_logs(self):
        if self._loading:
            messagebox.showwarning("Busy", "A load operation is already in progress. Click STOP first.")
            return

        log_name = self._log_var.get()
        try:
            max_r = int(self._max_var.get())
        except ValueError:
            max_r = 5000

        self._set_status(f"Loading {log_name}…", 0)
        self._loading = True
        self._all_events = []
        self._filtered_events = []
        self._page = 0
        self._update_table([])

        def worker():
            try:
                raw = self._reader.read_live(log_name, max_records=max_r)
                normalized = self._parser.normalize_batch(raw, progress_cb=self._on_progress)
                self._all_events = normalized
                self.root.after(0, self._post_load)
            except Exception as exc:
                self.root.after(0, lambda: self._set_status(f"Error: {exc}", -1))
                self.root.after(0, lambda: setattr(self, "_loading", False))

        self._load_thread = threading.Thread(target=worker, daemon=True)
        self._load_thread.start()

    def _import_evtx(self):
        path = filedialog.askopenfilename(
            title="Select EVTX File",
            filetypes=[("Event Log Files", "*.evtx"), ("All Files", "*.*")]
        )
        if not path:
            return

        self._loading = True
        self._all_events = []
        self._filtered_events = []
        self._page = 0
        self._update_table([])
        self._set_status(f"Loading {os.path.basename(path)}…", 0)

        def worker():
            try:
                raw = self._reader.read_evtx(path)
                normalized = self._parser.normalize_batch(raw, progress_cb=self._on_progress)
                self._all_events = normalized
                self.root.after(0, self._post_load)
            except Exception as exc:
                self.root.after(0, lambda: self._set_status(f"EVTX Error: {exc}", -1))
                self.root.after(0, lambda: setattr(self, "_loading", False))

        self._load_thread = threading.Thread(target=worker, daemon=True)
        self._load_thread.start()

    def _post_load(self):
        self._loading = False
        self._filtered_events = list(self._all_events)
        self._page = 0
        self._update_stats()
        self._update_table(self._page_events())
        self._set_status(f"Loaded {len(self._all_events):,} events.", 100)

    def _stop_loading(self):
        self._reader.stop()
        self._loading = False
        self._set_status("Load stopped by user.", -1)

    def _apply_filter(self):
        preset = self._build_preset_from_ui()
        self._filtered_events = self._filter.apply(self._all_events, preset)
        self._page = 0
        self._update_stats()
        self._update_table(self._page_events())
        self._set_status(
            f"Filter applied — {len(self._filtered_events):,} / {len(self._all_events):,} events match.", 100
        )

    def _quick_filter(self):
        if not self._all_events:
            return
        preset = self._build_preset_from_ui()
        preset.quick_search = self._qs_var.get()
        self._filtered_events = self._filter.apply(self._all_events, preset)
        self._page = 0
        self._update_stats()
        self._update_table(self._page_events())

    def _clear_filters(self):
        self._id_var.set("")
        self._kw_var.set("")
        self._start_var.set("")
        self._end_var.set("")
        self._err_var.set(False)
        self._warn_var.set(False)
        self._succ_var.set(False)
        self._fail_var.set(False)
        self._qs_var.set("")
        self._filtered_events = list(self._all_events)
        self._page = 0
        self._update_stats()
        self._update_table(self._page_events())
        self._set_status("Filters cleared.", 0)

    def _export(self):
        if not self._filtered_events:
            messagebox.showinfo("No Data", "No events to export. Load and filter logs first.")
            return

        path = filedialog.asksaveasfilename(
            title="Export Events",
            defaultextension=".csv",
            filetypes=[
                ("CSV", "*.csv"),
                ("JSON", "*.json"),
                ("Text Report", "*.txt"),
            ]
        )
        if not path:
            return

        try:
            count = self._exporter.auto_export(self._filtered_events, path)
            self._set_status(f"Exported {count:,} events → {os.path.basename(path)}", 100)
            messagebox.showinfo("Export Complete", f"Saved {count:,} events to:\n{path}")
        except Exception as exc:
            messagebox.showerror("Export Error", str(exc))

    # ── Table rendering ─────────────────────────────────────────────────────

    def _update_table(self, events: List[Dict]):
        self._tree.delete(*self._tree.get_children())

        for i, ev in enumerate(events):
            sev = ev.get("Severity", "INFO")
            level = ev.get("Level", "")

            # Colour tag
            if sev == SEVERITY_CRITICAL:
                tag = "CRITICAL"
            elif sev == SEVERITY_HIGH:
                tag = "HIGH"
            elif sev == SEVERITY_MEDIUM:
                tag = "MEDIUM"
            elif "success" in level.lower():
                tag = "SUCCESS"
            elif i % 2 == 0:
                tag = "ALT"
            else:
                tag = "INFO"

            self._tree.insert("", tk.END, iid=str(i), tags=(tag,), values=(
                ev.get("TimeCreated", ""),
                ev.get("EventID", ""),
                ev.get("Level", ""),
                sev,
                ev.get("Tag", ""),
                ev.get("Computer", ""),
                ev.get("User", ""),
                ev.get("Source", ""),
                ev.get("ShortMessage", ""),
            ))

        total_pages = max(1, (len(self._filtered_events) + PAGE_SIZE - 1) // PAGE_SIZE)
        self._page_var.set(f"Page {self._page + 1} / {total_pages}")

    def _update_stats(self):
        total = len(self._all_events)
        filtered = len(self._filtered_events)
        crit = sum(1 for e in self._filtered_events if e.get("Severity") == SEVERITY_CRITICAL)
        high = sum(1 for e in self._filtered_events if e.get("Severity") == SEVERITY_HIGH)
        self._stats_var.set(
            f"Showing {filtered:,} / {total:,}  │  🔴 {crit}  🟡 {high}"
        )

    # ── Pagination ──────────────────────────────────────────────────────────

    def _page_events(self) -> List[Dict]:
        start = self._page * PAGE_SIZE
        return self._filtered_events[start: start + PAGE_SIZE]

    def _page_first(self):
        self._page = 0
        self._update_table(self._page_events())

    def _page_prev(self):
        if self._page > 0:
            self._page -= 1
            self._update_table(self._page_events())

    def _page_next(self):
        total_pages = max(1, (len(self._filtered_events) + PAGE_SIZE - 1) // PAGE_SIZE)
        if self._page < total_pages - 1:
            self._page += 1
            self._update_table(self._page_events())

    def _page_last(self):
        total_pages = max(1, (len(self._filtered_events) + PAGE_SIZE - 1) // PAGE_SIZE)
        self._page = total_pages - 1
        self._update_table(self._page_events())

    # ── Sorting ─────────────────────────────────────────────────────────────

    def _sort_by(self, col: str):
        if self._sort_col == col:
            self._sort_rev = not self._sort_rev
        else:
            self._sort_col = col
            self._sort_rev = col == "TimeCreated"

        def sort_key(ev):
            val = ev.get(col, "")
            if col == "EventID":
                try:
                    return int(val)
                except Exception:
                    return 0
            if col == "TimeCreated" and ev.get("_datetime"):
                return ev["_datetime"]
            return str(val).lower()

        self._filtered_events.sort(key=sort_key, reverse=self._sort_rev)
        self._page = 0
        self._update_table(self._page_events())

    # ── Row selection / detail view ─────────────────────────────────────────

    def _get_selected_event(self) -> Optional[Dict]:
        sel = self._tree.selection()
        if not sel:
            return None
        idx = int(sel[0])
        start = self._page * PAGE_SIZE
        actual_idx = start + idx
        if actual_idx < len(self._filtered_events):
            return self._filtered_events[actual_idx]
        return None

    def _on_row_select(self, _event):
        ev = self._get_selected_event()
        if ev:
            self._populate_detail(ev)

    def _on_row_double(self, _event):
        self._nb.select(1)   # switch to detail tab

    def _populate_detail(self, ev: Dict):
        event_id = ev.get("EventID", "")
        sev = ev.get("Severity", "INFO")
        sev_colors = {
            SEVERITY_CRITICAL: C["critical"],
            SEVERITY_HIGH:     C["warning"],
            SEVERITY_MEDIUM:   C["accent2"],
        }

        self._det_id.config(text=f"  Event {event_id}")
        self._det_tag.config(text=ev.get("Tag", ""))
        self._det_sev.config(text=f"[{sev}]", fg=sev_colors.get(sev, C["text_dim"]))

        for key, var in self._det_fields.items():
            var.set(str(ev.get(key, "") or ""))

        self._det_text.config(state=tk.NORMAL)
        self._det_text.delete("1.0", tk.END)
        self._det_text.insert(tk.END, ev.get("FullMessage", ""))
        self._det_text.config(state=tk.DISABLED)

    # ── Context menu actions ─────────────────────────────────────────────────

    def _show_ctx(self, event):
        self._tree.identify_row(event.y)
        try:
            self._ctx_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self._ctx_menu.grab_release()

    def _copy_row(self):
        ev = self._get_selected_event()
        if ev:
            row_str = "\t".join(str(ev.get(c, "")) for c in
                                ["TimeCreated", "EventID", "Level", "Tag", "Computer", "User", "ShortMessage"])
            self.root.clipboard_clear()
            self.root.clipboard_append(row_str)

    def _copy_message(self):
        ev = self._get_selected_event()
        if ev:
            self.root.clipboard_clear()
            self.root.clipboard_append(ev.get("FullMessage", ""))

    def _filter_by_id(self):
        ev = self._get_selected_event()
        if ev:
            self._id_var.set(str(ev.get("EventID", "")))
            self._apply_filter()

    def _filter_by_computer(self):
        ev = self._get_selected_event()
        if ev:
            self._kw_var.set(ev.get("Computer", ""))
            self._apply_filter()

    def _filter_by_user(self):
        ev = self._get_selected_event()
        if ev:
            self._kw_var.set(ev.get("User", ""))
            self._apply_filter()

    # ── Preset management ───────────────────────────────────────────────────

    def _populate_preset_menu(self):
        custom = self._filter.load_all_presets()
        all_names = ["— select preset —"] + list(BUILTIN_PRESETS.keys()) + list(custom.keys())
        self._preset_cb["values"] = all_names

    def _build_preset_from_ui(self) -> FilterPreset:
        return FilterPreset(
            event_ids=self._id_var.get(),
            keyword=self._kw_var.get(),
            start_time=self._start_var.get(),
            end_time=self._end_var.get(),
            errors_only=self._err_var.get(),
            warnings_only=self._warn_var.get(),
            audit_success=self._succ_var.get(),
            audit_failure=self._fail_var.get(),
            quick_search=self._qs_var.get(),
        )

    def _load_preset_into_ui(self, preset: FilterPreset):
        self._id_var.set(preset.event_ids)
        self._kw_var.set(preset.keyword)
        self._start_var.set(preset.start_time)
        self._end_var.set(preset.end_time)
        self._err_var.set(preset.errors_only)
        self._warn_var.set(preset.warnings_only)
        self._succ_var.set(preset.audit_success)
        self._fail_var.set(preset.audit_failure)

    def _apply_preset(self, _event=None):
        name = self._preset_var.get()
        if name == "— select preset —":
            return

        if name in BUILTIN_PRESETS:
            preset = BUILTIN_PRESETS[name]
        else:
            preset = self._filter.get_preset(name)
        if preset:
            self._load_preset_into_ui(preset)
            self._apply_filter()

    def _save_preset(self):
        name = simpledialog.askstring(
            "Save Preset", "Enter a name for this filter preset:",
            parent=self.root
        )
        if not name or not name.strip():
            return
        preset = self._build_preset_from_ui()
        preset.name = name.strip()
        self._filter.save_preset(preset)
        self._populate_preset_menu()
        self._set_status(f"Preset '{name}' saved.", 100)

    def _delete_preset(self):
        name = self._preset_var.get()
        if name in BUILTIN_PRESETS or name == "— select preset —":
            messagebox.showwarning("Cannot Delete", "Cannot delete built-in presets.")
            return
        if messagebox.askyesno("Delete Preset", f"Delete preset '{name}'?"):
            self._filter.delete_preset(name)
            self._populate_preset_menu()
            self._preset_var.set("— select preset —")

    # ── Time shortcuts ──────────────────────────────────────────────────────

    def _set_time_range(self, hours: int):
        end = datetime.datetime.now()
        start = end - datetime.timedelta(hours=hours)
        self._start_var.set(start.strftime("%Y-%m-%d %H:%M:%S"))
        self._end_var.set(end.strftime("%Y-%m-%d %H:%M:%S"))

    def _clear_time_range(self):
        self._start_var.set("")
        self._end_var.set("")

    # ── Real-time refresh ───────────────────────────────────────────────────

    def _toggle_refresh(self):
        if self._refresh_var.get():
            self._schedule_refresh()

    def _schedule_refresh(self):
        if not self._refresh_var.get():
            return
        try:
            interval_sec = int(self._refresh_interval_var.get())
        except ValueError:
            interval_sec = 30
        self._load_logs()
        self.root.after(interval_sec * 1000, self._schedule_refresh)

    # ── Status / progress helpers ───────────────────────────────────────────

    def _set_status(self, msg: str, pct: float):
        self._status_var.set(msg)
        if pct < 0:
            self._prog.config(mode="determinate")
            self._prog["value"] = 0
        elif pct == 0:
            self._prog.config(mode="indeterminate")
            self._prog.start(10)
        elif pct >= 100:
            self._prog.stop()
            self._prog.config(mode="determinate")
            self._prog["value"] = 100
        else:
            self._prog.stop()
            self._prog.config(mode="determinate")
            self._prog["value"] = pct

    def _on_progress(self, msg: str, pct: float):
        """Thread-safe progress callback."""
        self.root.after(0, lambda: self._set_status(msg, pct))
