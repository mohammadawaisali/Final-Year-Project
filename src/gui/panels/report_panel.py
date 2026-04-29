# src/gui/panels/report_panel.py
import customtkinter as ctk
import threading, subprocess, sys
from gui.theme import *
from report_generator import ReportGenerator


class ReportPanel(ctk.CTkFrame):

    def __init__(self, master, app):
        super().__init__(master, fg_color=BG_DARK, corner_radius=0)
        self.app = app
        self._build()

    def _build(self):
        self.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(hdr, text="Export PDF Report",
                     font=FONT_TITLE, text_color=TEXT).pack(
                         side="left", padx=PAD*2, pady=PAD)

        # Options card
        opts = ctk.CTkFrame(self, fg_color=BG_PANEL,
                            corner_radius=CORNER_R)
        opts.grid(row=1, column=0, sticky="ew",
                  padx=PAD*2, pady=(PAD, 0))
        opts.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(opts, text="Output Directory",
                     font=FONT_SUB,
                     text_color=TEXT).grid(
                         row=0, column=0, columnspan=2,
                         sticky="w", padx=PAD, pady=(PAD, 4))

        self._out_var = ctk.StringVar(value="reports/")
        ctk.CTkEntry(opts, textvariable=self._out_var,
                     font=FONT_MONO,
                     fg_color=BG_CARD,
                     border_color=BORDER,
                     text_color=TEXT).grid(
                         row=1, column=0, sticky="ew",
                         padx=PAD, pady=(0, PAD))
        ctk.CTkButton(opts, text="Browse…", width=100,
                      fg_color=TEAL, hover_color=NAVY_MID,
                      command=self._browse_out).grid(
                          row=1, column=1,
                          padx=(0, PAD), pady=(0, PAD))

        self._status_lbl = ctk.CTkLabel(
            self,
            text="Run an analysis first, then export the report here.",
            font=FONT_BODY, text_color=TEXT_MUTED)
        self._status_lbl.grid(row=2, column=0,
                              padx=PAD*2, pady=PAD, sticky="w")

        self._progress = ctk.CTkProgressBar(
            self, mode="indeterminate",
            fg_color=BG_CARD, progress_color=TEAL)
        self._progress.grid(row=3, column=0, sticky="ew",
                            padx=PAD*2, pady=(0, PAD))
        self._progress.set(0)

        self._gen_btn = ctk.CTkButton(
            self, text="Generate & Save PDF Report",
            height=44, font=FONT_HEADING,
            fg_color=NAVY_MID, hover_color=TEAL,
            command=self._generate)
        self._gen_btn.grid(row=4, column=0,
                           padx=PAD*2, pady=(0, PAD), sticky="ew")

        self._open_btn = ctk.CTkButton(
            self, text="Open Report  ↗",
            height=36, font=FONT_BODY,
            fg_color="transparent",
            border_color=TEAL, border_width=1,
            hover_color=BG_CARD,
            state="disabled",
            command=self._open_report)
        self._open_btn.grid(row=5, column=0,
                            padx=PAD*2, pady=(0, PAD*2), sticky="ew")

    def _browse_out(self):
        from tkinter import filedialog
        d = filedialog.askdirectory()
        if d:
            self._out_var.set(d)

    def _generate(self):
        s = self.app.state
        if not s["hash_results"]:
            self._status_lbl.configure(
                text="⚠  No analysis results. Run an analysis first.",
                text_color=AMBER)
            return
        self._gen_btn.configure(state="disabled")
        self._progress.start()
        self._status_lbl.configure(text="Generating PDF…",
                                    text_color=TEXT_MUTED)
        threading.Thread(target=self._do_generate, daemon=True).start()

    def _do_generate(self):
        s   = self.app.state
        rg  = ReportGenerator(output_dir=self._out_var.get())
        path = rg.generate_pdf_report(
            s["sig_results"], s["ent_results"],
            s["hash_results"], s["meta_results"],
            graph_paths=s["graph_paths"])

        def done(p):
            self._progress.stop()
            self._progress.set(0)
            self._gen_btn.configure(state="normal")
            if p:
                self.app.state["report_path"] = p
                self._status_lbl.configure(
                    text=f"✅  Saved: {p}",
                    text_color=GREEN)
                self._open_btn.configure(state="normal")
            else:
                self._status_lbl.configure(
                    text="❌  Report generation failed — check console.",
                    text_color=CRIMSON)

        self.after(0, lambda: done(path))

    def _open_report(self):
        p = self.app.state.get("report_path")
        if p:
            if sys.platform == "darwin":
                subprocess.run(["open", p])
            elif sys.platform == "win32":
                subprocess.run(["start", p], shell=True)
            else:
                subprocess.run(["xdg-open", p])