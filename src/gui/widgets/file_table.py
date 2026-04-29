# src/gui/widgets/file_table.py
"""
Scrollable file results table with colour-coded risk rows.
Used in the Results panel to display per-file findings.
"""
import customtkinter as ctk
from gui.theme import *


class FileTable(ctk.CTkScrollableFrame):
    """
    A scrollable table that renders one row per file result.
    Columns and data are passed in at build time and can be
    refreshed by calling  .load(results)  again.
    """

    # Column definitions: (header_label, data_key, width, anchor)
    COLUMNS = [
        ("Filename",       "filename",    220, "w"),
        ("Type",           "file_type",    80, "center"),
        ("Risk",           "risk_label",   110, "center"),
        ("Score",          "score",         60, "center"),
        ("Findings",       "findings",     300, "w"),
    ]

    # Risk level → row background colour (subtle tint)
    ROW_BG = {
        "highly_suspicious": "#2a1a1a",   # dark crimson tint
        "suspicious":        "#2a1e0a",   # dark amber tint
        "low_risk":          "#0a1e2a",   # dark teal tint
        "normal":            BG_PANEL,    # neutral
    }

    # Risk level → badge text colour
    BADGE_COLOR = {
        "highly_suspicious": CRIMSON,
        "suspicious":        AMBER,
        "low_risk":          TEAL,
        "normal":            GREEN,
    }

    def __init__(self, master, on_row_click=None, **kwargs):
        """
        Parameters
        ----------
        master       : parent widget
        on_row_click : optional callback(result_dict) when a row is clicked
        """
        super().__init__(
            master,
            fg_color=BG_DARK,
            scrollbar_button_color=BORDER,
            scrollbar_button_hover_color=TEAL,
            **kwargs
        )
        self._on_row_click = on_row_click
        self._row_frames   = []   # keep references so we can destroy them
        self._build_header()

    # ── Header row ────────────────────────────────────────────────────────────
    def _build_header(self):
        self._header = ctk.CTkFrame(self,
                                    fg_color=BG_CARD,
                                    corner_radius=CORNER_R)
        self._header.pack(fill="x", padx=0, pady=(0, 2))

        for col_idx, (label, _, width, anchor) in enumerate(self.COLUMNS):
            ctk.CTkLabel(
                self._header,
                text=label,
                font=FONT_SUB,
                text_color=TEXT_MUTED,
                width=width,
                anchor=anchor,
            ).grid(row=0, column=col_idx,
                   padx=(PAD if col_idx == 0 else PAD_SM, PAD_SM),
                   pady=PAD_SM,
                   sticky="w")

    # ── Public API ────────────────────────────────────────────────────────────
    def load(self, results: list):
        """
        Clear the table and render a fresh set of results.

        Each item in  results  should be a dict produced by the
        intelligence layer with at least these keys:
            filename, file_type, risk_level, risk_score,
            suspicious_indicators  (list of strings)
        """
        self._clear_rows()

        if not results:
            self._show_empty()
            return

        for result in results:
            self._add_row(result)

    def clear(self):
        self._clear_rows()

    # ── Internal helpers ──────────────────────────────────────────────────────
    def _clear_rows(self):
        for frame in self._row_frames:
            frame.destroy()
        self._row_frames.clear()

    def _show_empty(self):
        frame = ctk.CTkFrame(self, fg_color=BG_PANEL,
                             corner_radius=CORNER_R)
        frame.pack(fill="x", padx=0, pady=2)
        ctk.CTkLabel(frame,
                     text="No results to display. Run an analysis first.",
                     font=FONT_BODY,
                     text_color=TEXT_MUTED).pack(
                         padx=PAD, pady=PAD*2)
        self._row_frames.append(frame)

    def _add_row(self, result: dict):
        lvl        = result.get("risk_level", "normal")
        score      = result.get("risk_score", 0.0)
        score_int  = int(round(score * 100))
        indicators = result.get("suspicious_indicators", [])

        # Truncate long finding lists for display
        if indicators:
            findings_text = indicators[0]
            if len(indicators) > 1:
                findings_text += f"  (+{len(indicators) - 1} more)"
        else:
            findings_text = "—  No anomalies detected"

        # Normalise file_type display
        file_type = result.get("file_type", "generic").replace("_", " ").title()

        row_data = {
            "filename":   result.get("filename", "Unknown"),
            "file_type":  file_type,
            "risk_label": lvl.replace("_", " ").upper(),
            "score":      f"{score_int} / 100",
            "findings":   findings_text,
        }

        # Row container
        row_bg = self.ROW_BG.get(lvl, BG_PANEL)
        frame = ctk.CTkFrame(self,
                             fg_color=row_bg,
                             corner_radius=CORNER_R - 2)
        frame.pack(fill="x", padx=0, pady=1)
        self._row_frames.append(frame)

        # Left risk accent bar
        accent = self.BADGE_COLOR.get(lvl, TEXT_MUTED)
        ctk.CTkFrame(frame, width=3,
                     fg_color=accent,
                     corner_radius=0).grid(
                         row=0, column=0,
                         rowspan=1, sticky="ns",
                         padx=(0, PAD_SM), pady=0)

        # Data cells
        for col_idx, (_, key, width, anchor) in enumerate(self.COLUMNS):
            text  = row_data[key]
            color = accent if key == "risk_label" else TEXT
            font  = FONT_SUB if key == "risk_label" else FONT_BODY

            lbl = ctk.CTkLabel(
                frame,
                text=text,
                font=font,
                text_color=color,
                width=width,
                anchor=anchor,
                wraplength=width - PAD if key == "findings" else 0,
            )
            lbl.grid(row=0, column=col_idx + 1,   # +1 for accent bar
                     padx=(PAD if col_idx == 0 else PAD_SM, PAD_SM),
                     pady=PAD_SM,
                     sticky="w")

        # Click binding — entire row is clickable if callback provided
        if self._on_row_click:
            for widget in (frame, *frame.winfo_children()):
                widget.bind("<Button-1>",
                            lambda e, r=result: self._on_row_click(r))
            # Hover highlight
            frame.bind("<Enter>",
                       lambda e, f=frame, bg=row_bg: f.configure(
                           fg_color=self._lighten(bg)))
            frame.bind("<Leave>",
                       lambda e, f=frame, bg=row_bg: f.configure(
                           fg_color=bg))

    @staticmethod
    def _lighten(hex_color: str) -> str:
        """Return a slightly lighter version of a hex colour for hover."""
        hex_color = hex_color.lstrip("#")
        r, g, b = (int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        r = min(255, r + 18)
        g = min(255, g + 18)
        b = min(255, b + 18)
        return f"#{r:02x}{g:02x}{b:02x}"