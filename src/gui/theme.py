# src/gui/theme.py
"""
Centralised colour, font, and sizing constants.
Change values here to restyle the entire application.
"""
import customtkinter as ctk

# ── Appearance ────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")          # "dark" | "light" | "system"
ctk.set_default_color_theme("blue")      # base theme — we override below

# ── Palette ───────────────────────────────────────────────────────────────────
NAVY        = "#0f2d4a"
NAVY_MID    = "#1a4a6e"
TEAL        = "#1a6b8a"
TEAL_LIGHT  = "#e8f4f8"
AMBER       = "#b85c00"
CRIMSON     = "#8b1a1a"
GREEN       = "#1a5c2e"
SLATE       = "#4a5568"
SLATE_LIGHT = "#f7f8fa"
BG_DARK     = "#0d1b2a"       # main window background
BG_PANEL    = "#13253a"       # panel / card background
BG_CARD     = "#1a3248"       # nested card background
BORDER      = "#2a4a6a"
TEXT        = "#e8f4f8"
TEXT_MUTED  = "#8baec4"
WHITE       = "#ffffff"

# ── Risk colours ─────────────────────────────────────────────────────────────
RISK_COLORS = {
    "highly_suspicious": CRIMSON,
    "suspicious":        AMBER,
    "low_risk":          TEAL,
    "normal":            GREEN,
}

# ── Fonts ─────────────────────────────────────────────────────────────────────
FONT_TITLE   = ("Helvetica Neue", 22, "bold")
FONT_HEADING = ("Helvetica Neue", 14, "bold")
FONT_SUB     = ("Helvetica Neue", 11, "bold")
FONT_BODY    = ("Helvetica Neue", 10)
FONT_SMALL   = ("Helvetica Neue", 9)
FONT_MONO    = ("Menlo", 9)          # monospace for file paths / hashes

# ── Sizing ────────────────────────────────────────────────────────────────────
SIDEBAR_W   = 200
WINDOW_W    = 1200
WINDOW_H    = 780
CORNER_R    = 8
PAD         = 16
PAD_SM      = 8