# src/gui/widgets/progress_bar.py
"""
Enhanced multi-stage progress widget.
Displays current step label, animated bar, and a step counter.
Designed for long-running background tasks like forensic analysis.
"""
import customtkinter as ctk
from gui.theme import *


class AnalysisProgressBar(ctk.CTkFrame):
    """
    A self-contained progress widget with:
      - Stage label   (e.g. "Step 2 / 4 — Entropy Analysis")
      - Animated bar  (indeterminate during work, determinate on completion)
      - Step dots     (visual breadcrumb of completed vs remaining steps)
      - Status icon   (spinner text → ✅ on done, ❌ on error)

    Usage
    -----
        bar = AnalysisProgressBar(parent, steps=["Signatures",
                                                  "Entropy",
                                                  "Hashes",
                                                  "Metadata"])
        bar.pack(fill="x", padx=16, pady=8)

        bar.start()                  # begin indeterminate animation
        bar.set_step(0, running=True)  # highlight step 0 as active
        bar.set_step(1, running=True)  # advance to step 1
        bar.complete()               # fill bar green, show ✅
        bar.error("msg")             # fill bar red,   show ❌
        bar.reset()                  # restore to idle state
    """

    # Dot states → colour
    DOT_PENDING  = BORDER
    DOT_ACTIVE   = TEAL
    DOT_DONE     = GREEN
    DOT_ERROR    = CRIMSON

    def __init__(self, master, steps: list[str], **kwargs):
        super().__init__(master,
                         fg_color=BG_PANEL,
                         corner_radius=CORNER_R,
                         **kwargs)
        self._steps       = steps
        self._current     = -1
        self._dot_labels  = []
        self._running     = False
        self._build()

    # ── Layout ────────────────────────────────────────────────────────────────
    def _build(self):
        self.grid_columnconfigure(0, weight=1)

        # ── Row 0: status icon + stage label ──────────────────────────────
        top = ctk.CTkFrame(self, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=PAD, pady=(PAD, 4))
        top.grid_columnconfigure(1, weight=1)

        self._icon_lbl = ctk.CTkLabel(
            top, text="⏸",
            font=("Helvetica Neue", 16),
            text_color=TEXT_MUTED, width=24)
        self._icon_lbl.grid(row=0, column=0, padx=(0, PAD_SM))

        self._stage_lbl = ctk.CTkLabel(
            top, text="Ready",
            font=FONT_SUB,
            text_color=TEXT_MUTED,
            anchor="w")
        self._stage_lbl.grid(row=0, column=1, sticky="ew")

        self._counter_lbl = ctk.CTkLabel(
            top, text="",
            font=FONT_SMALL,
            text_color=TEXT_MUTED)
        self._counter_lbl.grid(row=0, column=2, padx=(PAD_SM, 0))

        # ── Row 1: progress bar ────────────────────────────────────────────
        self._bar = ctk.CTkProgressBar(
            self,
            mode="indeterminate",
            fg_color=BG_CARD,
            progress_color=TEAL,
            height=6,
            corner_radius=3)
        self._bar.grid(row=1, column=0, sticky="ew", padx=PAD, pady=(0, PAD_SM))
        self._bar.set(0)

        # ── Row 2: step dots + labels ──────────────────────────────────────
        dots_frame = ctk.CTkFrame(self, fg_color="transparent")
        dots_frame.grid(row=2, column=0, sticky="ew",
                        padx=PAD, pady=(0, PAD))

        for i, step_name in enumerate(self._steps):
            col = i * 3   # dot | connector | (gap)

            # Connector line between dots (skip before first)
            if i > 0:
                ctk.CTkFrame(dots_frame,
                             width=24, height=2,
                             fg_color=BORDER).grid(
                                 row=0, column=col - 1,
                                 padx=0, pady=0)

            # Dot
            dot = ctk.CTkLabel(
                dots_frame,
                text="●",
                font=("Helvetica Neue", 12),
                text_color=self.DOT_PENDING)
            dot.grid(row=0, column=col, padx=(0, 2))
            self._dot_labels.append(dot)

            # Step name below dot
            ctk.CTkLabel(
                dots_frame,
                text=step_name,
                font=FONT_SMALL,
                text_color=TEXT_MUTED,
                wraplength=80,
                justify="center",
            ).grid(row=1, column=col, padx=(0, 2), pady=(2, 0))

    # ── Public API ────────────────────────────────────────────────────────────
    def start(self):
        """Begin indeterminate animation (call before first step)."""
        self._running = True
        self._bar.configure(mode="indeterminate", progress_color=TEAL)
        self._bar.start()
        self._icon_lbl.configure(text="⏳", text_color=TEAL)
        self._stage_lbl.configure(text="Starting…", text_color=TEXT)

    def set_step(self, index: int, running: bool = True):
        """
        Advance the breadcrumb to  index.
        All previous dots are marked done; this dot is highlighted.

        Parameters
        ----------
        index   : 0-based step index
        running : if True the dot pulses teal (active);
                  if False it is marked done immediately
        """
        self._current = index
        total = len(self._steps)

        # Update counter label
        self._counter_lbl.configure(
            text=f"Step {index + 1} / {total}")

        # Update stage label
        name = self._steps[index] if index < total else "Finalising"
        self._stage_lbl.configure(
            text=f"Step {index + 1} / {total}  —  {name}",
            text_color=TEXT)

        # Update dot colours
        for i, dot in enumerate(self._dot_labels):
            if i < index:
                dot.configure(text_color=self.DOT_DONE)
            elif i == index:
                dot.configure(text_color=self.DOT_ACTIVE if running
                              else self.DOT_DONE)
            else:
                dot.configure(text_color=self.DOT_PENDING)

    def complete(self, message: str = "Analysis complete"):
        """Fill bar to 100 % in green and show success state."""
        self._running = False
        self._bar.stop()
        self._bar.configure(mode="determinate", progress_color=GREEN)
        self._bar.set(1.0)
        self._icon_lbl.configure(text="✅", text_color=GREEN)
        self._stage_lbl.configure(text=message, text_color=GREEN)
        self._counter_lbl.configure(text="")
        for dot in self._dot_labels:
            dot.configure(text_color=self.DOT_DONE)

    def error(self, message: str = "Analysis failed"):
        """Fill bar in red and show error state."""
        self._running = False
        self._bar.stop()
        self._bar.configure(mode="determinate", progress_color=CRIMSON)
        self._bar.set(1.0)
        self._icon_lbl.configure(text="❌", text_color=CRIMSON)
        self._stage_lbl.configure(text=message, text_color=CRIMSON)
        self._counter_lbl.configure(text="")
        if self._current >= 0:
            self._dot_labels[self._current].configure(
                text_color=self.DOT_ERROR)

    def reset(self):
        """Restore to idle state (before any analysis)."""
        self._running = False
        self._current = -1
        self._bar.stop()
        self._bar.configure(mode="indeterminate", progress_color=TEAL)
        self._bar.set(0)
        self._icon_lbl.configure(text="⏸", text_color=TEXT_MUTED)
        self._stage_lbl.configure(text="Ready", text_color=TEXT_MUTED)
        self._counter_lbl.configure(text="")
        for dot in self._dot_labels:
            dot.configure(text_color=self.DOT_PENDING)

    def set_message(self, message: str):
        """Update only the stage label text without changing state."""
        self._stage_lbl.configure(text=message)