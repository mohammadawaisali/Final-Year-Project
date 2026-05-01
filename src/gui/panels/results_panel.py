# src/gui/panels/results_panel.py
"""
Results Panel — displays findings across all four detection modules
plus a dedicated VirusTotal threat intelligence tab.
"""
import customtkinter as ctk
from gui.theme import *


# ── Verdict colours ───────────────────────────────────────────────────────────
VT_COLOURS = {
    "MALICIOUS":  CRIMSON,
    "SUSPICIOUS": AMBER,
    "CLEAN":      GREEN,
    "UNKNOWN":    TEXT_MUTED,
    "SKIPPED":    BORDER,
    "ERROR":      AMBER,
}

VT_ROW_BG = {
    "MALICIOUS":  "#2a1010",
    "SUSPICIOUS": "#2a1e08",
    "CLEAN":      "#0a1e12",
    "UNKNOWN":    BG_PANEL,
    "SKIPPED":    BG_PANEL,
    "ERROR":      BG_PANEL,
}


class ResultsPanel(ctk.CTkFrame):

    def __init__(self, master, app):
        super().__init__(master, fg_color=BG_DARK, corner_radius=0)
        self.app = app
        self._build()

    # ── Layout ────────────────────────────────────────────────────────────────
    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # Header
        hdr = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(hdr, text="Analysis Results",
                     font=FONT_TITLE,
                     text_color=TEXT).pack(side="left",
                                           padx=PAD * 2, pady=PAD)
        self._hdr_sub = ctk.CTkLabel(
            hdr, text="", font=FONT_SMALL, text_color=TEXT_MUTED)
        self._hdr_sub.pack(side="right", padx=PAD * 2, pady=PAD)

        # Tabs
        self._tabs = ctk.CTkTabview(
            self,
            fg_color=BG_PANEL,
            segmented_button_fg_color=BG_CARD,
            segmented_button_selected_color=TEAL,
            segmented_button_selected_hover_color=NAVY_MID,
            text_color=TEXT_MUTED,
            text_color_disabled=BORDER)
        self._tabs.grid(row=1, column=0, sticky="nsew",
                        padx=PAD * 2, pady=PAD)

        for tab in ["🛡 VirusTotal", "🔏 Signatures",
                    "📊 Entropy", "🔗 Hashes", "🗂 Metadata"]:
            self._tabs.add(tab)

        # Plain textbox tabs (Signatures, Entropy, Metadata)
        self._outputs = {}
        for tab in ["🔏 Signatures", "📊 Entropy", "🗂 Metadata"]:
            tb = ctk.CTkTextbox(
                self._tabs.tab(tab),
                font=FONT_MONO,
                fg_color=BG_DARK,
                text_color=TEXT,
                wrap="none")
            tb.pack(fill="both", expand=True)
            self._outputs[tab] = tb

        # Hashes tab — scrollable table
        self._build_hashes_tab()

        # VirusTotal tab — scrollable cards
        self._build_vt_tab()

    # ── Hashes tab ────────────────────────────────────────────────────────────
    def _build_hashes_tab(self):
        tab = self._tabs.tab("🔗 Hashes")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        # Column headers
        hdr = ctk.CTkFrame(tab, fg_color=BG_CARD, corner_radius=CORNER_R)
        hdr.grid(row=0, column=0, sticky="ew", pady=(0, 2))

        cols = [("Filename", 220), ("MD5 (first 16)", 140),
                ("SHA-256 (first 20)", 180), ("Size", 80),
                ("VT Verdict", 110)]
        for col_idx, (label, width) in enumerate(cols):
            ctk.CTkLabel(hdr, text=label, font=FONT_SUB,
                         text_color=TEXT_MUTED,
                         width=width, anchor="w").grid(
                             row=0, column=col_idx,
                             padx=(PAD if col_idx == 0 else PAD_SM, PAD_SM),
                             pady=PAD_SM)

        self._hash_scroll = ctk.CTkScrollableFrame(
            tab, fg_color=BG_DARK,
            scrollbar_button_color=BORDER,
            scrollbar_button_hover_color=TEAL)
        self._hash_scroll.grid(row=1, column=0, sticky="nsew")
        self._hash_rows = []

    # ── VirusTotal tab ────────────────────────────────────────────────────────
    def _build_vt_tab(self):
        tab = self._tabs.tab("🛡 VirusTotal")
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        # Summary bar at the top
        self._vt_summary_frame = ctk.CTkFrame(
            tab, fg_color=BG_PANEL, corner_radius=CORNER_R)
        self._vt_summary_frame.grid(row=0, column=0, sticky="ew",
                                    pady=(0, PAD_SM))

        self._vt_kpi = {}
        kpi_specs = [
            ("malicious",  "⛔  Malicious",  CRIMSON),
            ("suspicious", "⚠   Suspicious", AMBER),
            ("clean",      "✓   Clean",       GREEN),
            ("unknown",    "?   Unknown",     TEXT_MUTED),
            ("skipped",    "—   Skipped",     BORDER),
        ]
        for col, (key, label, colour) in enumerate(kpi_specs):
            self._vt_summary_frame.grid_columnconfigure(col, weight=1)
            frame = ctk.CTkFrame(
                self._vt_summary_frame,
                fg_color=BG_CARD, corner_radius=CORNER_R)
            frame.grid(row=0, column=col,
                       padx=PAD_SM, pady=PAD_SM, sticky="ew")

            # Top accent bar
            ctk.CTkFrame(frame, height=3,
                         fg_color=colour,
                         corner_radius=2).pack(fill="x")

            val_lbl = ctk.CTkLabel(
                frame, text="—",
                font=("Helvetica Neue", 20, "bold"),
                text_color=colour)
            val_lbl.pack(pady=(PAD_SM, 2))
            ctk.CTkLabel(frame, text=label,
                         font=FONT_SMALL,
                         text_color=TEXT_MUTED).pack(pady=(0, PAD_SM))
            self._vt_kpi[key] = val_lbl

        # Scrollable result cards
        self._vt_scroll = ctk.CTkScrollableFrame(
            tab, fg_color=BG_DARK,
            scrollbar_button_color=BORDER,
            scrollbar_button_hover_color=TEAL)
        self._vt_scroll.grid(row=1, column=0, sticky="nsew")
        self._vt_cards = []

    # ── Public refresh ────────────────────────────────────────────────────────
    def on_show(self):
        """Called every time this panel is navigated to."""
        s = self.app.state

        # Update header subtitle
        if s.get("last_run"):
            total = len(s["hash_results"])
            self._hdr_sub.configure(
                text=f"{total} files  ·  {s['last_run']}")

        self._render_signatures(s["sig_results"])
        self._render_entropy(s["ent_results"])
        self._render_hashes(s["hash_results"])
        self._render_metadata(s["meta_results"])
        self._render_virustotal(
            s["hash_results"],
            s.get("vt_summary", {}),
            s.get("vt_enabled", False))

    # ── Renderers ─────────────────────────────────────────────────────────────
    def _write(self, tab: str, text: str):
        tb = self._outputs[tab]
        tb.configure(state="normal")
        tb.delete("1.0", "end")
        tb.insert("end", text)
        tb.configure(state="disabled")

    def _render_signatures(self, results):
        if not results:
            self._write("🔏 Signatures", "No results yet."); return
        mismatches = [r for r in results if r.get("mismatch")]
        clean      = [r for r in results if not r.get("mismatch")]
        lines      = []

        if mismatches:
            lines.append(f"{'─'*70}")
            lines.append(f"  ✗  {len(mismatches)} MISMATCH(ES) DETECTED")
            lines.append(f"{'─'*70}")
            for r in mismatches:
                lines.append(f"\n  ✗  {r.get('filename','')}")
                lines.append(f"       Extension : {r.get('extension','N/A')}")
                lines.append(f"       Actual    : {r.get('detected_type','N/A')}")
                lines.append(f"       Path      : {r.get('filepath','N/A')}")

        lines.append(f"\n{'─'*70}")
        lines.append(f"  ✓  {len(clean)} file(s) with matching signatures")
        lines.append(f"{'─'*70}")
        for r in clean:
            lines.append(f"  ✓  {r.get('filename','')}")

        self._write("🔏 Signatures", "\n".join(lines))

    def _render_entropy(self, results):
        if not results:
            self._write("📊 Entropy", "No results yet."); return
        sorted_r = sorted(results,
                           key=lambda x: x.get("entropy", 0), reverse=True)
        lines = [f"  {'Filename':<40} {'Entropy':>8}   Status"]
        lines.append(f"  {'─'*60}")
        for r in sorted_r:
            flag = "⚠  HIGH — Possible encryption/steganography" \
                   if r.get("high_entropy") else "   Normal"
            lines.append(
                f"  {r.get('filename',''):<40} "
                f"{r.get('entropy', 0):>8.4f}   {flag}")
        self._write("📊 Entropy", "\n".join(lines))

    def _render_hashes(self, results):
        """Render the scrollable hash table with VT verdict column."""
        # Clear old rows
        for widget in self._hash_rows:
            widget.destroy()
        self._hash_rows.clear()

        if not results:
            lbl = ctk.CTkLabel(self._hash_scroll,
                               text="No results yet.",
                               font=FONT_BODY, text_color=TEXT_MUTED)
            lbl.pack(padx=PAD, pady=PAD)
            self._hash_rows.append(lbl)
            return

        col_widths = [220, 140, 180, 80, 110]

        for r in results:
            verdict    = r.get("vt_verdict", "SKIPPED")
            row_bg     = VT_ROW_BG.get(verdict, BG_PANEL)
            vt_colour  = VT_COLOURS.get(verdict, TEXT_MUTED)

            row = ctk.CTkFrame(self._hash_scroll,
                               fg_color=row_bg,
                               corner_radius=CORNER_R - 2)
            row.pack(fill="x", padx=0, pady=1)
            self._hash_rows.append(row)

            # Accent bar
            ctk.CTkFrame(row, width=3,
                         fg_color=vt_colour,
                         corner_radius=0).grid(row=0, column=0,
                                               sticky="ns",
                                               padx=(0, PAD_SM), pady=0)

            values = [
                r.get("filename", "N/A"),
                str(r.get("md5", "N/A"))[:16],
                str(r.get("sha256", "N/A"))[:20],
                f"{r.get('size_bytes', 0):,} B",
                verdict,
            ]
            for col_idx, (val, width) in enumerate(zip(values, col_widths)):
                colour = vt_colour if col_idx == 4 else TEXT
                font   = FONT_SUB  if col_idx == 4 else FONT_BODY
                ctk.CTkLabel(row, text=val, font=font,
                             text_color=colour,
                             width=width, anchor="w").grid(
                                 row=0, column=col_idx + 1,
                                 padx=(PAD if col_idx == 0 else PAD_SM, PAD_SM),
                                 pady=PAD_SM, sticky="w")

    def _render_metadata(self, results):
        if not results:
            self._write("🗂 Metadata", "No results yet."); return
        lines = []
        for r in results:
            inds   = r.get("suspicious_indicators", [])
            status = "⚠  " + " | ".join(inds) if inds else "✓  Clean"
            lines.append(f"{'─'*70}")
            lines.append(f"  {r.get('filename','')}  "
                         f"[{r.get('file_type','').upper()}]")
            lines.append(f"  {status}")
            if inds and len(inds) > 1:
                for ind in inds[1:]:
                    lines.append(f"     + {ind}")
        self._write("🗂 Metadata", "\n".join(lines))

    def _render_virustotal(self, hash_results: list,
                           vt_summary: dict, vt_enabled: bool):
        """
        Render the VirusTotal tab:
          - KPI summary bar at top
          - One card per file that was actually checked
          - 'Not run' message if VT was not enabled
        """
        # ── Update KPI counters ────────────────────────────────────────────
        for key, lbl in self._vt_kpi.items():
            lbl.configure(text=str(vt_summary.get(key, 0))
                          if vt_summary else "—")

        # ── Clear old cards ────────────────────────────────────────────────
        for widget in self._vt_cards:
            widget.destroy()
        self._vt_cards.clear()

        # ── Not enabled message ────────────────────────────────────────────
        if not vt_enabled or not any(
                r.get("vt_verdict") not in (None, "SKIPPED")
                for r in hash_results):
            msg = ctk.CTkFrame(self._vt_scroll,
                               fg_color=BG_PANEL,
                               corner_radius=CORNER_R)
            msg.pack(fill="x", padx=0, pady=PAD_SM)
            self._vt_cards.append(msg)

            ctk.CTkLabel(
                msg,
                text="VirusTotal scan was not run.\n\n"
                     "Enable the  'Query VirusTotal API'  checkbox in\n"
                     "Run Analysis, then run the analysis again.",
                font=FONT_BODY,
                text_color=TEXT_MUTED,
                justify="center").pack(padx=PAD * 2, pady=PAD * 2)
            return

        # ── One card per file ──────────────────────────────────────────────
        # Show malicious/suspicious first
        order = {"MALICIOUS": 0, "SUSPICIOUS": 1,
                 "UNKNOWN": 2, "CLEAN": 3, "SKIPPED": 4, "ERROR": 5}
        sorted_results = sorted(
            hash_results,
            key=lambda r: order.get(r.get("vt_verdict", "SKIPPED"), 6))

        for r in sorted_results:
            verdict = r.get("vt_verdict", "SKIPPED")
            if verdict == "SKIPPED":
                continue          # don't clutter with non-checked files

            self._add_vt_card(r)

    def _add_vt_card(self, result: dict):
        """Build one VirusTotal result card for a file."""
        verdict    = result.get("vt_verdict", "UNKNOWN")
        ratio      = result.get("vt_detection_ratio", "N/A")
        threats    = result.get("vt_threat_names", [])
        last_scan  = result.get("vt_last_analysis", "N/A")
        vt_link    = result.get("vt_link", "")
        fname      = result.get("filename", "Unknown")
        sha256     = result.get("sha256", "N/A")
        accent     = VT_COLOURS.get(verdict, TEXT_MUTED)
        row_bg     = VT_ROW_BG.get(verdict, BG_PANEL)

        card = ctk.CTkFrame(self._vt_scroll,
                            fg_color=row_bg,
                            corner_radius=CORNER_R)
        card.pack(fill="x", padx=0, pady=3)
        card.grid_columnconfigure(1, weight=1)
        self._vt_cards.append(card)

        # Left accent strip
        ctk.CTkFrame(card, width=4,
                     fg_color=accent,
                     corner_radius=0).grid(row=0, column=0,
                                           rowspan=3, sticky="ns",
                                           padx=(0, PAD), pady=0)

        # ── Row 0: filename + verdict badge + ratio ────────────────────────
        top = ctk.CTkFrame(card, fg_color="transparent")
        top.grid(row=0, column=1, sticky="ew",
                 padx=(0, PAD), pady=(PAD, 2))
        top.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(top, text=fname,
                     font=FONT_SUB, text_color=TEXT,
                     anchor="w").grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(top,
                     text=f"{verdict}   {ratio}",
                     font=FONT_SUB,
                     text_color=accent,
                     anchor="e").grid(row=0, column=1, sticky="e")

        # ── Row 1: SHA-256 ─────────────────────────────────────────────────
        ctk.CTkLabel(card,
                     text=f"SHA-256: {sha256}",
                     font=FONT_MONO, text_color=TEXT_MUTED,
                     anchor="w").grid(row=1, column=1, sticky="w",
                                      padx=(0, PAD), pady=0)

        # ── Row 2: threat names + last scan + link ─────────────────────────
        bot = ctk.CTkFrame(card, fg_color="transparent")
        bot.grid(row=2, column=1, sticky="ew",
                 padx=(0, PAD), pady=(2, PAD))
        bot.grid_columnconfigure(0, weight=1)

        if threats:
            ctk.CTkLabel(bot,
                         text="Detections: " + ",  ".join(threats),
                         font=FONT_SMALL,
                         text_color=accent,
                         anchor="w",
                         wraplength=550).grid(row=0, column=0,
                                              sticky="w")

        info_parts = []
        if last_scan != "N/A":
            info_parts.append(f"Last scan: {last_scan}")
        if vt_link:
            info_parts.append(f"↗  {vt_link}")

        if info_parts:
            ctk.CTkLabel(bot,
                         text="   ".join(info_parts),
                         font=FONT_SMALL,
                         text_color=TEXT_MUTED,
                         anchor="w",
                         wraplength=550).grid(row=1, column=0, sticky="w")