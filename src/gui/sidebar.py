# src/gui/sidebar.py
import customtkinter as ctk
from gui.theme import *


class Sidebar(ctk.CTkFrame):

    NAV_ITEMS = [
        ("home",     "🏠",  "Dashboard"),
        ("analysis", "🔍",  "Run Analysis"),
        ("results",  "📊",  "Results"),
        ("report",   "📄",  "Export Report"),
    ]

    def __init__(self, master, navigate_cmd):
        super().__init__(master,
                         width=SIDEBAR_W,
                         fg_color=BG_PANEL,
                         corner_radius=0)
        self.navigate_cmd = navigate_cmd
        self._buttons = {}
        self.grid_propagate(False)
        self._build()

    def _build(self):
        # App title / logo area
        ctk.CTkLabel(self,
                     text="🔬 ForensicFA",
                     font=FONT_HEADING,
                     text_color=TEAL).pack(pady=(24, 4), padx=PAD)
        ctk.CTkLabel(self,
                     text="File Analysis Tool",
                     font=FONT_SMALL,
                     text_color=TEXT_MUTED).pack(pady=(0, 20), padx=PAD)

        ctk.CTkFrame(self, height=1, fg_color=BORDER).pack(
            fill="x", padx=PAD, pady=(0, 12))

        # Nav buttons
        for key, icon, label in self.NAV_ITEMS:
            btn = ctk.CTkButton(
                self,
                text=f"  {icon}  {label}",
                anchor="w",
                width=SIDEBAR_W - PAD * 2,
                height=40,
                corner_radius=CORNER_R,
                fg_color="transparent",
                hover_color=BG_CARD,
                text_color=TEXT_MUTED,
                font=FONT_BODY,
                command=lambda k=key: self.navigate_cmd(k),
            )
            btn.pack(padx=PAD, pady=2)
            self._buttons[key] = btn

        # Version label at bottom
        ctk.CTkLabel(self,
                     text="v1.0  ·  Roehampton",
                     font=FONT_SMALL,
                     text_color=BORDER).pack(side="bottom", pady=14)

    def set_active(self, key: str):
        for k, btn in self._buttons.items():
            if k == key:
                btn.configure(fg_color=NAVY_MID, text_color=WHITE)
            else:
                btn.configure(fg_color="transparent", text_color=TEXT_MUTED)