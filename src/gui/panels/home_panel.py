# src/gui/panels/home_panel.py
import customtkinter as ctk
from gui.theme import *
from gui.widgets.stat_card import StatCard


class HomePanel(ctk.CTkFrame):

    def __init__(self, master, app):
        super().__init__(master, fg_color=BG_DARK, corner_radius=0)
        self.app = app
        self._cards = {}
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)

        # Header
        hdr = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(hdr,
                     text="Forensic File Analyzer",
                     font=FONT_TITLE,
                     text_color=TEXT).pack(side="left",
                                           padx=PAD*2, pady=PAD)
        ctk.CTkLabel(hdr,
                     text="University of Roehampton  ·  Muhammad Awais Ali",
                     font=FONT_SMALL,
                     text_color=TEXT_MUTED).pack(side="right",
                                                  padx=PAD*2, pady=PAD)

        # KPI cards row
        cards_frame = ctk.CTkFrame(self, fg_color=BG_DARK)
        cards_frame.grid(row=1, column=0, sticky="ew",
                         padx=PAD*2, pady=(PAD*2, 0))
        for i in range(4):
            cards_frame.grid_columnconfigure(i, weight=1)

        specs = [
            ("0",  "Files Analysed",       TEAL,    "total"),
            ("0",  "Signature Mismatches", CRIMSON,  "sig"),
            ("0",  "High Entropy Files",   AMBER,    "ent"),
            ("0",  "Metadata Anomalies",   AMBER,    "meta"),
        ]
        for col, (val, label, color, key) in enumerate(specs):
            card = StatCard(cards_frame, value=val,
                            label=label, accent=color)
            card.grid(row=0, column=col,
                      padx=PAD_SM, pady=PAD_SM, sticky="ew")
            self._cards[key] = card

        # Last-run info
        self._info_label = ctk.CTkLabel(
            self,
            text="No analysis run yet.  →  Go to Run Analysis to begin.",
            font=FONT_BODY, text_color=TEXT_MUTED)
        self._info_label.grid(row=2, column=0,
                              padx=PAD*2, pady=PAD, sticky="w")

        # Quick-start button
        ctk.CTkButton(
            self,
            text="Start New Analysis  →",
            height=40,
            fg_color=TEAL,
            hover_color=NAVY_MID,
            font=FONT_SUB,
            command=lambda: self.app._show_panel("analysis")
        ).grid(row=3, column=0,
               padx=PAD*2, pady=0, sticky="w")

    def on_show(self):
        """Refresh KPI cards every time the panel is navigated to."""
        s = self.app.state
        sig  = sum(1 for r in s["sig_results"]  if r.get("mismatch"))
        ent  = sum(1 for r in s["ent_results"]  if r.get("high_entropy"))
        meta = sum(1 for r in s["meta_results"] if r.get("suspicious_indicators"))
        total = len(s["hash_results"])

        self._cards["total"].update(str(total), TEAL)
        self._cards["sig"].update(str(sig),
                                  CRIMSON if sig else GREEN)
        self._cards["ent"].update(str(ent),
                                  AMBER if ent else GREEN)
        self._cards["meta"].update(str(meta),
                                   AMBER if meta else GREEN)

        if s["last_run"]:
            self._info_label.configure(
                text=f"Last analysis: {s['last_run']}",
                text_color=TEXT_MUTED)