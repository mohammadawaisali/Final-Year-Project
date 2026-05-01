# src/gui/app.py
import customtkinter as ctk
from gui.theme import *
from gui.sidebar import Sidebar
from gui.panels.home_panel    import HomePanel
from gui.panels.analysis_panel import AnalysisPanel
from gui.panels.results_panel  import ResultsPanel
from gui.panels.report_panel   import ReportPanel


class ForensicApp(ctk.CTk):

    def __init__(self):
        super().__init__()
        self.title("Forensic File Analyzer  —  University of Roehampton")
        self.geometry(f"{WINDOW_W}x{WINDOW_H}")
        self.minsize(900, 600)
        self.configure(fg_color=BG_DARK)

        # Shared state: analysis results live here, all panels read from it
        self.state = {
            "target_path":   None,
            "sig_results":   [],
            "ent_results":   [],
            "hash_results":  [],
            "meta_results":  [],
            "graph_paths":   {},
            "report_path":   None,
            "vt_summary":    {},       
            "vt_enabled":    False,     
            "last_run":      None,
        }

        self._build_layout()
        self._show_panel("home")

    # ── Layout ────────────────────────────────────────────────────────────────
    def _build_layout(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Left sidebar
        self.sidebar = Sidebar(self, navigate_cmd=self._show_panel)
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        # Right content area — all panels stacked, only one visible at a time
        self.content = ctk.CTkFrame(self, fg_color=BG_DARK, corner_radius=0)
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

        self.panels = {
            "home":     HomePanel(self.content,     app=self),
            "analysis": AnalysisPanel(self.content, app=self),
            "results":  ResultsPanel(self.content,  app=self),
            "report":   ReportPanel(self.content,   app=self),
        }
        for panel in self.panels.values():
            panel.grid(row=0, column=0, sticky="nsew")

    # ── Navigation ────────────────────────────────────────────────────────────
    def _show_panel(self, name: str):
        self.panels[name].tkraise()
        self.sidebar.set_active(name)
        # Let each panel refresh its content when navigated to
        if hasattr(self.panels[name], "on_show"):
            self.panels[name].on_show()