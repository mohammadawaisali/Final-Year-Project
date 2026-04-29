# src/gui/panels/results_panel.py
import customtkinter as ctk
from gui.theme import *


class ResultsPanel(ctk.CTkFrame):

    def __init__(self, master, app):
        super().__init__(master, fg_color=BG_DARK, corner_radius=0)
        self.app = app
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        hdr = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(hdr, text="Analysis Results",
                     font=FONT_TITLE, text_color=TEXT).pack(
                         side="left", padx=PAD*2, pady=PAD)

        self._tabs = ctk.CTkTabview(
            self,
            fg_color=BG_PANEL,
            segmented_button_fg_color=BG_CARD,
            segmented_button_selected_color=TEAL,
            segmented_button_selected_hover_color=NAVY_MID,
            text_color=TEXT_MUTED,
            text_color_disabled=BORDER)
        self._tabs.grid(row=1, column=0, sticky="nsew",
                        padx=PAD*2, pady=PAD)

        for tab in ["Signatures", "Entropy", "Hashes", "Metadata"]:
            self._tabs.add(tab)

        # Textboxes inside each tab (simple but readable)
        self._outputs = {}
        for tab in ["Signatures", "Entropy", "Hashes", "Metadata"]:
            tb = ctk.CTkTextbox(
                self._tabs.tab(tab),
                font=FONT_MONO,
                fg_color=BG_DARK,
                text_color=TEXT,
                wrap="none")
            tb.pack(fill="both", expand=True)
            self._outputs[tab] = tb

    def on_show(self):
        s = self.app.state
        self._render_signatures(s["sig_results"])
        self._render_entropy(s["ent_results"])
        self._render_hashes(s["hash_results"])
        self._render_metadata(s["meta_results"])

    # ── Renderers ─────────────────────────────────────────────────────────────
    def _write(self, tab: str, text: str):
        tb = self._outputs[tab]
        tb.configure(state="normal")
        tb.delete("1.0", "end")
        tb.insert("end", text)
        tb.configure(state="disabled")

    def _render_signatures(self, results):
        if not results:
            self._write("Signatures", "No results yet."); return
        lines = [f"{'Filename':<35} {'Extension':<12} {'Detected Type':<30} {'Match?'}"]
        lines.append("─" * 85)
        for r in results:
            match = "✓  OK" if not r.get("mismatch") else "✗  MISMATCH"
            lines.append(
                f"{r.get('filename',''):<35} "
                f"{r.get('extension',''):<12} "
                f"{str(r.get('detected_type',''))[:30]:<30} "
                f"{match}")
        self._write("Signatures", "\n".join(lines))

    def _render_entropy(self, results):
        if not results:
            self._write("Entropy", "No results yet."); return
        lines = [f"{'Filename':<40} {'Entropy':>8}   {'Status'}"]
        lines.append("─" * 70)
        for r in sorted(results,
                        key=lambda x: x.get("entropy", 0), reverse=True):
            flag = "⚠  HIGH" if r.get("high_entropy") else "   ok"
            lines.append(
                f"{r.get('filename',''):<40} "
                f"{r.get('entropy', 0):>8.4f}   {flag}")
        self._write("Entropy", "\n".join(lines))

    def _render_hashes(self, results):
        if not results:
            self._write("Hashes", "No results yet."); return
        lines = [f"{'Filename':<35} {'MD5 (first 16)':<20} {'Size':>10}"]
        lines.append("─" * 70)
        for r in results:
            lines.append(
                f"{r.get('filename',''):<35} "
                f"{str(r.get('md5',''))[:16]:<20} "
                f"{r.get('size_bytes', 0):>10,} B")
        self._write("Hashes", "\n".join(lines))

    def _render_metadata(self, results):
        if not results:
            self._write("Metadata", "No results yet."); return
        lines = []
        for r in results:
            inds = r.get("suspicious_indicators", [])
            status = "⚠  " + ", ".join(inds) if inds else "✓  Clean"
            lines.append(f"{'─'*60}")
            lines.append(f"  {r.get('filename','')}  [{r.get('file_type','').upper()}]")
            lines.append(f"  {status}")
        self._write("Metadata", "\n".join(lines))