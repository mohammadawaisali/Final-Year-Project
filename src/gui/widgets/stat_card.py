# src/gui/widgets/stat_card.py
import customtkinter as ctk
from gui.theme import *


class StatCard(ctk.CTkFrame):
    """A single KPI tile — value + label + colour accent."""

    def __init__(self, master, value: str, label: str,
                 accent: str = TEAL, **kwargs):
        super().__init__(master,
                         fg_color=BG_CARD,
                         corner_radius=CORNER_R,
                         border_width=1,
                         border_color=BORDER,
                         **kwargs)
        # Top accent bar
        ctk.CTkFrame(self, height=3,
                     fg_color=accent,
                     corner_radius=2).pack(fill="x", padx=0, pady=(0, 0))

        self._val_label = ctk.CTkLabel(
            self, text=value,
            font=("Helvetica Neue", 28, "bold"),
            text_color=accent)
        self._val_label.pack(pady=(12, 2))

        ctk.CTkLabel(self, text=label,
                     font=FONT_SMALL,
                     text_color=TEXT_MUTED).pack(pady=(0, 12))

    def update(self, value: str, accent: str = None):
        self._val_label.configure(text=value)
        if accent:
            self._val_label.configure(text_color=accent)