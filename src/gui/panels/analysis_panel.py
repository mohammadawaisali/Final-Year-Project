# src/gui/panels/analysis_panel.py
import customtkinter as ctk
import threading
import sys
import os
from pathlib import Path
from gui.theme import *
from gui.widgets.progress_bar import AnalysisProgressBar

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
        card = ctk.CTkFrame(self, fg_color=BG_PANEL, corner_radius=CORNER_R)
        card.grid(row=1, column=0, sticky="ew", padx=PAD * 2, pady=(PAD, 0))
        card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(card, text="Target Directory",
                     font=FONT_SUB,
                     text_color=TEXT).grid(row=0, column=0, columnspan=3,
                                           sticky="w", padx=PAD,
                                           pady=(PAD, 4))

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
                                                  padx=PAD, pady=(0, PAD))

        ctk.CTkButton(card, text="Browse…",
                      width=100,
                      fg_color=TEAL,
                      hover_color=NAVY_MID,
                      command=self._browse).grid(row=1, column=2,
                                                  padx=(0, PAD),
                                                  pady=(0, PAD))

        # ── VirusTotal option row ─────────────────────────────────────────
        ctk.CTkFrame(card, height=1,
                     fg_color=BORDER).grid(row=2, column=0, columnspan=3,
                                           sticky="ew", padx=PAD,
                                           pady=(0, PAD_SM))

        self._vt_var = ctk.BooleanVar(value=False)
        vt_check = ctk.CTkCheckBox(
            card,
            text="Query VirusTotal API for each file",
            variable=self._vt_var,
            font=FONT_BODY,
            text_color=TEXT,
            fg_color=TEAL,
            hover_color=NAVY_MID,
            checkmark_color=WHITE,
            command=self._on_vt_toggle)
        vt_check.grid(row=3, column=0, columnspan=2,
                      sticky="w", padx=PAD, pady=(0, PAD_SM))

        self._vt_key_label = ctk.CTkLabel(
            card, text="", font=FONT_SMALL, text_color=TEXT_MUTED)
        self._vt_key_label.grid(row=3, column=2,
                                padx=(0, PAD), pady=(0, PAD_SM), sticky="e")

        self._vt_warn_label = ctk.CTkLabel(
            card, text="",
            font=FONT_SMALL, text_color=AMBER,
            wraplength=500, justify="left")
        self._vt_warn_label.grid(row=4, column=0, columnspan=3,
                                  sticky="w", padx=PAD, pady=(0, PAD))

        # Populate key status badge on startup
        self._on_vt_toggle()

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
            font=FONT_BODY, text_color=TEXT_MUTED)
        self._status_label.grid(row=0, column=0, sticky="w",
                                padx=PAD, pady=(PAD, 4))

        # 5 steps — VirusTotal is the optional 5th
        self._progress = AnalysisProgressBar(
            prog_frame,
            steps=["Signatures", "Entropy", "Hashes", "Metadata", "VirusTotal"])
        self._progress.grid(row=1, column=0, sticky="ew",
                            padx=PAD, pady=(0, PAD))

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
                           padx=PAD * 2, pady=(0, PAD * 2), sticky="ew")

    # ── VT toggle ─────────────────────────────────────────────────────────────
    def _on_vt_toggle(self):
        """Update key badge and warning text when VT checkbox changes."""
        has_key = bool(os.environ.get("VIRUSTOTAL_API_KEY", "").strip())
        vt_on   = self._vt_var.get()

        if has_key:
            self._vt_key_label.configure(
                text="🔑  API key loaded", text_color=GREEN)
        else:
            self._vt_key_label.configure(
                text="⚠  API key not set", text_color=AMBER)

        if vt_on:
            if not has_key:
                self._vt_warn_label.configure(
                    text="⚠  Set VIRUSTOTAL_API_KEY environment variable "
                         "before running. VT checks will be skipped without it.")
            else:
                self._vt_warn_label.configure(
                    text="ℹ  Free tier: 4 requests / min. "
                         "Large directories will take longer (~15 s per file).")
        else:
            self._vt_warn_label.configure(text="")

    # ── Helpers ───────────────────────────────────────────────────────────────
    def _browse(self):
        from tkinter import filedialog
        path = filedialog.askdirectory(title="Select directory to analyse")
        if path:
            self._path_var.set(path)
            self.app.state["target_path"] = path

    def _log_write(self, msg: str):
        self._log.configure(state="normal")
        self._log.insert("end", msg + "\n")
        self._log.see("end")
        self._log.configure(state="disabled")

    def _set_status(self, msg: str):
        self._status_label.configure(text=msg)

    def _log_vt_verdict(self, filename: str, vt_data: dict):
        """Format and log a single VT verdict line."""
        verdict = vt_data.get("vt_verdict", "UNKNOWN")
        ratio   = vt_data.get("vt_detection_ratio", "N/A")
        threats = vt_data.get("vt_threat_names", [])

        if verdict == "MALICIOUS":
            threat_str = f"  →  {', '.join(threats[:2])}" if threats else ""
            line = f"      ⛔  MALICIOUS   [{ratio}]  {filename}{threat_str}"
        elif verdict == "SUSPICIOUS":
            line = f"      ⚠   SUSPICIOUS  [{ratio}]  {filename}"
        elif verdict == "CLEAN":
            line = f"      ✓   CLEAN       [{ratio}]  {filename}"
        elif verdict == "UNKNOWN":
            line = f"      ?   UNKNOWN (not in VT database)  {filename}"
        else:
            line = f"      —   {verdict}  {filename}"

        self.after(0, lambda m=line: self._log_write(m))

    # ── Analysis start ────────────────────────────────────────────────────────
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

        use_vt = self._vt_var.get()
        threading.Thread(
            target=self._run_analysis,
            args=(path, use_vt),
            daemon=True).start()

    # ── Background analysis ───────────────────────────────────────────────────
    def _run_analysis(self, path: str, use_vt: bool):
        """All work happens here in a background thread."""

        def status(msg):
            self.after(0, lambda m=msg: self._set_status(m))

        def log(msg):
            self.after(0, lambda m=msg: self._log_write(m))

        def step(idx):
            self.after(0, lambda i=idx: self._progress.set_step(
                i, running=False))

        vt_summary = {"malicious": 0, "suspicious": 0,
                      "clean": 0, "unknown": 0, "skipped": 0}

        try:
            log(f"[START] Target: {path}")
            has_key = bool(os.environ.get("VIRUSTOTAL_API_KEY", "").strip())
            if use_vt:
                log(f"[VT]   VirusTotal: "
                    f"{'ENABLED' if has_key else 'DISABLED — API key missing'}")

            # ── 1 — Signatures ────────────────────────────────────────────
            status("Step 1 / 5 — File Signature Analysis…")
            self.after(0, lambda: self._progress.set_step(0, running=True))
            log("[1/5] Running signature analysis…")
            sa = SignatureAnalyzer()
            sig_results = sa.analyze_directory(path)
            mismatches  = sum(1 for r in sig_results if r.get("mismatch"))
            log(f"      ✓  {len(sig_results)} files  |  {mismatches} mismatches")
            step(0)

            # ── 2 — Entropy ───────────────────────────────────────────────
            status("Step 2 / 5 — Shannon Entropy Analysis…")
            self.after(0, lambda: self._progress.set_step(1, running=True))
            log("[2/5] Running entropy analysis…")
            ec = EntropyCalculator()
            ent_results = ec.analyze_directory(path)
            high        = sum(1 for r in ent_results if r.get("high_entropy"))
            log(f"      ✓  {len(ent_results)} files  |  {high} high-entropy")
            step(1)

            # ── 3 — Hashes ────────────────────────────────────────────────
            status("Step 3 / 5 — Hash & Duplicate Detection…")
            self.after(0, lambda: self._progress.set_step(2, running=True))
            log("[3/5] Running hash verification…")
            hv           = HashVerifier()
            hash_results = hv.analyze_directory(path, check_virustotal=False)
            dups         = len(hv.find_duplicates())
            log(f"      ✓  {len(hash_results)} files hashed  |  "
                f"{dups} duplicate set(s)")
            step(2)

            # ── 4 — Metadata ──────────────────────────────────────────────
            status("Step 4 / 5 — Metadata Integrity Analysis…")
            self.after(0, lambda: self._progress.set_step(3, running=True))
            log("[4/5] Running metadata analysis…")
            mp           = MetadataParser()
            meta_results = mp.analyze_directory(path)
            anomalies    = sum(1 for r in meta_results
                               if r.get("suspicious_indicators"))
            log(f"      ✓  {len(meta_results)} files  |  {anomalies} anomalies")
            step(3)

            # ── 5 — VirusTotal (optional) ─────────────────────────────────
            self.after(0, lambda: self._progress.set_step(4, running=True))

            if use_vt and has_key:
                total_files = len(hash_results)
                est_min     = total_files * 15 // 60
                est_sec     = total_files * 15 % 60
                status(f"Step 5 / 5 — VirusTotal ({total_files} files)…")
                log(f"[5/5] Querying VirusTotal for {total_files} file(s)…")
                log(f"      Estimated time: ~{est_min}m {est_sec}s "
                    f"(free tier: 4 req/min)")

                for i, result in enumerate(hash_results, 1):
                    sha256  = result.get("sha256", "")
                    fname   = result.get("filename", "unknown")

                    # Progress update every file
                    status(f"Step 5 / 5 — VirusTotal  [{i}/{total_files}]  {fname}")

                    if not sha256 or sha256 == "N/A":
                        log(f"      [{i}/{total_files}] Skipped (no hash): {fname}")
                        vt_summary["skipped"] += 1
                        continue

                    log(f"      [{i}/{total_files}] Checking: {fname}")
                    vt_data = hv._query_virustotal(sha256)

                    # Merge VT fields into the hash result in-place
                    result.update(vt_data)

                    # Log verdict line
                    self._log_vt_verdict(fname, vt_data)

                    # Tally
                    v = vt_data.get("vt_verdict", "UNKNOWN").lower()
                    vt_summary[v] = vt_summary.get(v, 0) + 1

                log(f"\n[VT]  ── Summary ─────────────────────────")
                log(f"      ⛔  Malicious  : {vt_summary.get('malicious', 0)}")
                log(f"      ⚠   Suspicious : {vt_summary.get('suspicious', 0)}")
                log(f"      ✓   Clean      : {vt_summary.get('clean', 0)}")
                log(f"      ?   Unknown    : {vt_summary.get('unknown', 0)}")
                log(f"      —   Skipped    : {vt_summary.get('skipped', 0)}")
                log(f"[VT]  ────────────────────────────────────")

            else:
                if use_vt and not has_key:
                    log("[5/5] VirusTotal skipped — VIRUSTOTAL_API_KEY not set.")
                else:
                    log("[5/5] VirusTotal not requested.")

            step(4)

            # ── Visualisations ────────────────────────────────────────────
            status("Generating visualisations…")
            log("[VIZ] Generating charts…")
            viz         = ForensicVisualizer()
            graph_paths = viz.generate_all_visualizations(
                sig_results, ent_results, hash_results, meta_results)
            log("      ✓  Charts saved")

            # ── Save everything to shared state ───────────────────────────
            self.app.state.update({
                "sig_results":  sig_results,
                "ent_results":  ent_results,
                "hash_results": hash_results,
                "meta_results": meta_results,
                "graph_paths":  graph_paths,
                "vt_summary":   vt_summary,
                "vt_enabled":   use_vt,
                "last_run":     path,
            })

            log("[DONE] Analysis complete.")
            self.after(0, lambda: self._progress.complete(
                "Complete — navigate to Results or Export Report."))
            status("✅  Analysis complete.")
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