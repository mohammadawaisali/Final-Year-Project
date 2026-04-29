# src/gui/panels/analysis_panel.py
import customtkinter as ctk
import threading
import sys
import os
from pathlib import Path
from gui.theme import *
from gui.widgets.progress_bar import AnalysisProgressBar

# Make sure src/ is on the path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from signature_analyzer import SignatureAnalyzer
from entropy_calculator import EntropyCalculator
from hash_verifier      import HashVerifier
from metadata_parser    import MetadataParser
from visualizer         import ForensicVisualizer
from report_generator   import ReportGenerator


class AnalysisPanel(ctk.CTkFrame):

    def __init__(self, master, app):
        super().__init__(master, fg_color=BG_DARK, corner_radius=0)
        self.app = app
        self._build()

    # ── UI ────────────────────────────────────────────────────────────────────
    def _build(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        # ── Page header ───────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        ctk.CTkLabel(hdr, text="Run Analysis",
                     font=FONT_TITLE,
                     text_color=TEXT).pack(side="left",
                                           padx=PAD * 2, pady=PAD)

        # ── Target selection card ─────────────────────────────────────────
        card = ctk.CTkFrame(self, fg_color=BG_PANEL,
                            corner_radius=CORNER_R)
        card.grid(row=1, column=0, sticky="ew",
                  padx=PAD * 2, pady=(PAD, 0))
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(card, text="Target Directory",
                     font=FONT_SUB,
                     text_color=TEXT).grid(row=0, column=0,
                                           columnspan=3, sticky="w",
                                           padx=PAD, pady=(PAD, 4))

        self._path_var = ctk.StringVar(value="No directory selected")
        ctk.CTkEntry(card,
                     textvariable=self._path_var,
                     state="readonly",
                     font=FONT_MONO,
                     fg_color=BG_CARD,
                     border_color=BORDER,
                     text_color=TEXT_MUTED).grid(row=1, column=0,
                                                  columnspan=2,
                                                  sticky="ew",
                                                  padx=PAD,
                                                  pady=(0, PAD))

        ctk.CTkButton(card, text="Browse…",
                      width=100,
                      fg_color=TEAL,
                      hover_color=NAVY_MID,
                      command=self._browse).grid(row=1, column=2,
                                                  padx=(0, PAD),
                                                  pady=(0, PAD))

        # ── Progress area ─────────────────────────────────────────────────
        prog_frame = ctk.CTkFrame(self, fg_color=BG_PANEL,
                                  corner_radius=CORNER_R)
        prog_frame.grid(row=2, column=0, sticky="nsew",
                        padx=PAD * 2, pady=PAD)
        prog_frame.grid_columnconfigure(0, weight=1)
        prog_frame.grid_rowconfigure(2, weight=1)

        self._status_label = ctk.CTkLabel(
            prog_frame,
            text="Ready — select a directory to begin.",
            font=FONT_BODY,
            text_color=TEXT_MUTED)
        self._status_label.grid(row=0, column=0, sticky="w",
                                padx=PAD, pady=(PAD, 4))

        # ── Enhanced progress bar widget ───────────────────────────────────
        self._progress = AnalysisProgressBar(
            prog_frame,
            steps=["Signatures", "Entropy", "Hashes", "Metadata"])
        self._progress.grid(row=1, column=0, sticky="ew",
                            padx=PAD, pady=(0, PAD))

        # ── Log output ─────────────────────────────────────────────────────
        self._log = ctk.CTkTextbox(
            prog_frame,
            font=FONT_MONO,
            fg_color=BG_DARK,
            text_color=TEXT_MUTED,
            wrap="none",
            state="disabled")
        self._log.grid(row=2, column=0, sticky="nsew",
                       padx=PAD, pady=(0, PAD))

        # ── Run button ────────────────────────────────────────────────────
        self._run_btn = ctk.CTkButton(
            self,
            text="▶  Run Full Analysis",
            height=44,
            font=FONT_HEADING,
            fg_color=NAVY_MID,
            hover_color=TEAL,
            command=self._start_analysis)
        self._run_btn.grid(row=3, column=0,
                           padx=PAD * 2, pady=(0, PAD * 2),
                           sticky="ew")

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _browse(self):
        from tkinter import filedialog
        path = filedialog.askdirectory(title="Select directory to analyse")
        if path:
            self._path_var.set(path)
            self.app.state["target_path"] = path

    def _log_write(self, msg: str):
        """Thread-safe log append."""
        self._log.configure(state="normal")
        self._log.insert("end", msg + "\n")
        self._log.see("end")
        self._log.configure(state="disabled")

    def _set_status(self, msg: str):
        self._status_label.configure(text=msg)

    # ── Analysis runner ───────────────────────────────────────────────────────
    def _start_analysis(self):
        path = self.app.state.get("target_path")
        if not path:
            self._set_status("⚠  Please select a directory first.")
            return

        self._run_btn.configure(state="disabled", text="⏳  Analysing…")
        self._progress.reset()
        self._progress.start()

        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        self._log.configure(state="disabled")

        thread = threading.Thread(target=self._run_analysis,
                                  args=(path,), daemon=True)
        thread.start()

    def _run_analysis(self, path: str):
        """
        Runs entirely in a background thread.
        All widget updates are dispatched via  self.after(0, lambda: ...)
        so the main thread (Tk event loop) stays responsive.
        """
        def status(msg):
            self.after(0, lambda m=msg: self._set_status(m))

        def log(msg):
            self.after(0, lambda m=msg: self._log_write(m))

        def step(idx):
            self.after(0, lambda i=idx: self._progress.set_step(
                i, running=False))

        try:
            log(f"[START] Target: {path}")

            # 1 — Signature analysis
            status("Step 1 / 4 — File Signature Analysis…")
            self.after(0, lambda: self._progress.set_step(0, running=True))
            log("[1/4] Running signature analysis…")
            sa = SignatureAnalyzer()
            sig_results = sa.analyze_directory(path)
            mismatches = sum(1 for r in sig_results if r.get("mismatch"))
            log(f"      ✓  {len(sig_results)} files  |  {mismatches} mismatches")
            step(0)

            # 2 — Entropy analysis
            status("Step 2 / 4 — Shannon Entropy Analysis…")
            self.after(0, lambda: self._progress.set_step(1, running=True))
            log("[2/4] Running entropy analysis…")
            ec = EntropyCalculator()
            ent_results = ec.analyze_directory(path)
            high = sum(1 for r in ent_results if r.get("high_entropy"))
            log(f"      ✓  {len(ent_results)} files  |  {high} high-entropy")
            step(1)

            # 3 — Hash / duplicate detection
            status("Step 3 / 4 — Hash & Duplicate Detection…")
            self.after(0, lambda: self._progress.set_step(2, running=True))
            log("[3/4] Running hash verification…")
            hv = HashVerifier()
            hash_results = hv.analyze_directory(path)
            log(f"      ✓  {len(hash_results)} files hashed")
            step(2)

            # 4 — Metadata analysis
            status("Step 4 / 4 — Metadata Integrity Analysis…")
            self.after(0, lambda: self._progress.set_step(3, running=True))
            log("[4/4] Running metadata analysis…")
            mp = MetadataParser()
            meta_results = mp.analyze_directory(path)
            anomalies = sum(1 for r in meta_results
                            if r.get("suspicious_indicators"))
            log(f"      ✓  {len(meta_results)} files  |  {anomalies} anomalies")
            step(3)

            # 5 — Visualisations
            status("Generating visualisations…")
            log("[VIZ] Generating charts…")
            viz = ForensicVisualizer()
            graph_paths = viz.generate_all_visualizations(
                sig_results, ent_results, hash_results, meta_results)
            log("      ✓  Charts saved")

            # Store results in shared app state
            self.app.state.update({
                "sig_results":  sig_results,
                "ent_results":  ent_results,
                "hash_results": hash_results,
                "meta_results": meta_results,
                "graph_paths":  graph_paths,
                "last_run":     path,
            })

            log("[DONE] Analysis complete.")
            self.after(0, lambda: self._progress.complete(
                "Analysis complete — navigate to Results or Export Report."))
            status("✅  Analysis complete.")

            # Auto-navigate to results after a short pause
            self.after(900, lambda: self.app._show_panel("results"))

        except Exception as e:
            import traceback
            log(f"[ERROR] {e}")
            log(traceback.format_exc())
            self.after(0, lambda err=str(e): self._progress.error(
                f"Error: {err}"))
            status(f"❌  Error: {e}")

        finally:
            self.after(0, lambda: self._run_btn.configure(
                state="normal", text="▶  Run Full Analysis"))