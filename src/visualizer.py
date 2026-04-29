"""
Forensic Visualizer Module — Professional Redesign
Generates publication-quality charts that match the report's design language.

Palette (mirrors report_generator.py):
  Navy    #0f2d4a   primary headers / axes
  Teal    #1a6b8a   normal / accent
  Amber   #c06000   suspicious / warning
  Crimson #8b1a1a   high-risk / critical
  Green   #1a5c2e   clean / normal
  Slate   #4a5568   secondary text
  Light   #f7f8fa   background wash

Chart design principles:
  - Horizontal layouts for file lists (scales cleanly with file count)
  - Consistent type-face sizing so labels never overlap
  - Minimal grid lines, no chartjunk
  - Matching accent colours across all three figures
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
from matplotlib.lines import Line2D
from pathlib import Path
import numpy as np
import os

# ── Shared palette ────────────────────────────────────────────────────────────
P = {
    'navy':         '#0f2d4a',
    'navy_mid':     '#1a4a6e',
    'teal':         '#1a6b8a',
    'teal_light':   '#e8f4f8',
    'teal_mid':     '#6aaec7',
    'amber':        '#c06000',
    'amber_light':  '#fef3e2',
    'amber_mid':    '#e8a040',
    'crimson':      '#8b1a1a',
    'crimson_light':'#fdf0f0',
    'green':        '#1a5c2e',
    'green_light':  '#edf7f0',
    'green_mid':    '#4a9960',
    'slate':        '#4a5568',
    'slate_light':  '#f7f8fa',
    'border':       '#cbd5e0',
    'white':        '#ffffff',
    'text':         '#1a202c',
    'text_muted':   '#718096',
}

# ── Global matplotlib defaults ────────────────────────────────────────────────
plt.rcParams.update({
    'font.family':       'DejaVu Sans',
    'font.size':         9,
    'axes.titlesize':    11,
    'axes.titleweight':  'bold',
    'axes.titlecolor':   P['navy'],
    'axes.labelsize':    9,
    'axes.labelcolor':   P['slate'],
    'axes.edgecolor':    P['border'],
    'axes.facecolor':    P['white'],
    'axes.spines.top':   False,
    'axes.spines.right': False,
    'xtick.color':       P['slate'],
    'ytick.color':       P['slate'],
    'xtick.labelsize':   8,
    'ytick.labelsize':   8,
    'figure.facecolor':  P['slate_light'],
    'figure.dpi':        150,
    'savefig.dpi':       300,
    'savefig.bbox':      'tight',
    'savefig.facecolor': P['slate_light'],
    'legend.fontsize':   8,
    'legend.framealpha': 0.92,
    'legend.edgecolor':  P['border'],
    'grid.color':        P['border'],
    'grid.linewidth':    0.5,
    'grid.alpha':        0.6,
})


def _navy_spine(ax):
    """Style axis spines to match report palette."""
    for spine in ['left', 'bottom']:
        ax.spines[spine].set_color(P['border'])
        ax.spines[spine].set_linewidth(0.8)


def _section_title(ax, text, subtitle=''):
    """Render a navy bold title with optional muted subtitle."""
    full = text if not subtitle else f'{text}\n{subtitle}'
    ax.set_title(full, fontsize=11, fontweight='bold',
                 color=P['navy'], loc='left', pad=10)


# ═════════════════════════════════════════════════════════════════════════════
class ForensicVisualizer:

    def __init__(self, output_dir='reports/graphs'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    # ─────────────────────────────────────────────────────────────────────────
    # FIGURE 1 — Detection Summary Dashboard
    # ─────────────────────────────────────────────────────────────────────────
    def generate_detection_summary(self, signature_results, entropy_results,
                                   hash_results, metadata_results,
                                   output_filename='detection_summary.png'):
        try:
            total   = len(hash_results)
            sig_s   = sum(1 for r in signature_results if r.get('mismatch'))
            ent_s   = sum(1 for r in entropy_results   if r.get('high_entropy'))
            meta_s  = sum(1 for r in metadata_results  if r.get('status') == 'suspicious')

            seen, dups = set(), 0
            for r in hash_results:
                h = r.get('md5')
                if h in seen: dups += 1
                seen.add(h)

            fig = plt.figure(figsize=(14, 9))
            fig.suptitle('Forensic Analysis Summary Dashboard',
                         fontsize=14, fontweight='bold',
                         color=P['navy'], y=0.98)

            gs = gridspec.GridSpec(2, 3, figure=fig,
                                   hspace=0.52, wspace=0.38,
                                   left=0.06, right=0.97,
                                   top=0.90, bottom=0.08)

            # ── Row 0: three donut charts ─────────────────────────────────
            donut_specs = [
                ('File Signatures',  sig_s,  total - sig_s,  'Mismatched', 'Clean'),
                ('Entropy Analysis', ent_s,  total - ent_s,  'High Entropy', 'Normal'),
                ('Hash Duplicates',  dups,   total - dups,   'Duplicate', 'Unique'),
            ]
            for col, (title, bad, good, bad_lbl, good_lbl) in enumerate(donut_specs):
                ax = fig.add_subplot(gs[0, col])
                sizes  = [bad, good] if bad > 0 else [0.001, total]
                colors = [P['amber'], P['teal_mid']] if bad > 0 \
                         else [P['border'], P['teal_mid']]
                wedges, _ = ax.pie(
                    sizes, colors=colors, startangle=90,
                    wedgeprops={'width': 0.55, 'linewidth': 1.5,
                                'edgecolor': P['white']},
                    counterclock=False
                )
                # Centre label
                pct = f'{bad/total*100:.1f}%' if total > 0 else '0%'
                ax.text(0, 0.08, str(bad),
                        ha='center', va='center',
                        fontsize=18, fontweight='bold',
                        color=P['amber'] if bad else P['green'])
                ax.text(0, -0.28, pct,
                        ha='center', va='center',
                        fontsize=9, color=P['text_muted'])
                ax.set_title(title, fontsize=10, fontweight='bold',
                             color=P['navy'], pad=6)
                # Legend
                patches = [
                    mpatches.Patch(color=P['amber'], label=f'{bad_lbl} ({bad})'),
                    mpatches.Patch(color=P['teal_mid'], label=f'{good_lbl} ({good})'),
                ]
                ax.legend(handles=patches, loc='lower center',
                          bbox_to_anchor=(0.5, -0.22),
                          ncol=1, frameon=False, fontsize=8)

            # ── Row 1, col 0-1: horizontal bar chart ──────────────────────
            ax_bar = fig.add_subplot(gs[1, :2])
            categories = ['Signature\nMismatches', 'High\nEntropy',
                          'Duplicates', 'Metadata\nAnomalies']
            counts     = [sig_s, ent_s, dups, meta_s]
            bar_colors = [P['crimson'], P['amber'], P['navy_mid'], P['teal']]

            y_pos = np.arange(len(categories))
            bars  = ax_bar.barh(y_pos, counts, color=bar_colors,
                                height=0.55, edgecolor=P['white'],
                                linewidth=0.8)

            # Value labels
            for bar, val in zip(bars, counts):
                ax_bar.text(bar.get_width() + max(counts) * 0.02,
                            bar.get_y() + bar.get_height() / 2,
                            str(val), va='center', fontsize=10,
                            fontweight='bold', color=P['text'])

            ax_bar.set_yticks(y_pos)
            ax_bar.set_yticklabels(categories, fontsize=9)
            ax_bar.set_xlabel('Files Flagged', color=P['slate'])
            ax_bar.set_xlim(0, max(counts) * 1.25 if max(counts) else 1)
            ax_bar.invert_yaxis()
            ax_bar.grid(axis='x', linestyle='--', alpha=0.5)
            _navy_spine(ax_bar)
            _section_title(ax_bar, 'Suspicious Files by Detection Method')

            # ── Row 1, col 2: statistics table ────────────────────────────
            ax_tbl = fig.add_subplot(gs[1, 2])
            ax_tbl.axis('off')

            tbl_data = [
                ['Metric',              'Count'],
                ['Total Files',         str(total)],
                ['Signature Mismatches',str(sig_s)],
                ['High Entropy Files',  str(ent_s)],
                ['Duplicate Files',     str(dups)],
                ['Metadata Anomalies',  str(meta_s)],
                ['Total Flags',         str(sig_s + ent_s + dups + meta_s)],
            ]
            row_colors = [
                [P['navy'],      P['navy']],
                [P['slate_light'], P['white']],
                [P['white'],      P['slate_light']],
                [P['slate_light'], P['white']],
                [P['white'],      P['slate_light']],
                [P['slate_light'], P['white']],
                [P['amber_light'], P['amber_light']],
            ]
            tbl = ax_tbl.table(
                cellText=tbl_data, cellLoc='left',
                loc='center', cellColours=row_colors,
                colWidths=[0.68, 0.32]
            )
            tbl.auto_set_font_size(False)
            tbl.set_fontsize(9)
            tbl.scale(1, 1.9)
            # Header text white, total text bold
            for col in range(2):
                tbl[(0, col)].get_text().set_color(P['white'])
                tbl[(0, col)].get_text().set_fontweight('bold')
                tbl[(6, col)].get_text().set_fontweight('bold')
                tbl[(6, col)].get_text().set_color(P['amber'])
            ax_tbl.set_title('Analysis Statistics', fontsize=10,
                             fontweight='bold', color=P['navy'],
                             loc='left', pad=6)

            out = os.path.join(self.output_dir, output_filename)
            plt.savefig(out)
            plt.close()
            print(f'[OK] Detection summary: {out}')
            return out
        except Exception as e:
            print(f'[ERR] Detection summary: {e}')
            import traceback; traceback.print_exc()
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # FIGURE 2 — Entropy Distribution (horizontal, scales with file count)
    # ─────────────────────────────────────────────────────────────────────────
    def generate_entropy_histogram(self, entropy_results,
                                   output_filename='entropy_histogram.png'):
        try:
            if not entropy_results:
                print('[WARN] No entropy data')
                return None

            # Sort: suspicious first, then by entropy descending
            results = sorted(
                [r for r in entropy_results if 'entropy' in r],
                key=lambda r: (not r.get('high_entropy', False),
                               -r.get('entropy', 0))
            )
            n = len(results)

            # Dynamic figure height: 0.42 inches per file, min 5, max 18
            fig_h = max(5, min(18, n * 0.42 + 2.2))
            fig, ax = plt.subplots(figsize=(11, fig_h))

            labels   = [r['filename'][:38] for r in results]
            values   = [r.get('entropy', 0) for r in results]
            bar_cols = [P['crimson'] if r.get('high_entropy') else P['teal']
                        for r in results]
            y_pos    = np.arange(n)

            bars = ax.barh(y_pos, values, color=bar_cols,
                           height=0.62, edgecolor=P['white'],
                           linewidth=0.6, alpha=0.9)

            # Threshold line
            threshold = 7.5
            ax.axvline(threshold, color=P['amber'], linewidth=1.8,
                       linestyle='--', zorder=5, label=f'Threshold ({threshold})')

            # Value labels — only show if entropy != 0
            for bar, val in zip(bars, values):
                if val > 0.05:
                    x_pos = bar.get_width() + 0.04
                    ax.text(x_pos, bar.get_y() + bar.get_height() / 2,
                            f'{val:.3f}', va='center', fontsize=7.5,
                            color=P['text'], clip_on=True)

            # Shade high-entropy region
            ax.axvspan(threshold, 8.1, alpha=0.06, color=P['crimson'], zorder=0)

            ax.set_yticks(y_pos)
            ax.set_yticklabels(labels, fontsize=8)
            ax.set_xlabel('Shannon Entropy Value  (0 = uniform, 8 = maximum randomness)',
                          color=P['slate'], fontsize=9)
            ax.set_xlim(0, 8.4)
            ax.invert_yaxis()
            ax.grid(axis='x', linestyle='--', alpha=0.4)
            _navy_spine(ax)

            # Stripe suspicious rows
            for i, r in enumerate(results):
                if r.get('high_entropy'):
                    ax.axhspan(i - 0.45, i + 0.45,
                               color=P['crimson_light'], alpha=0.35, zorder=0)

            legend_handles = [
                mpatches.Patch(color=P['teal'],    label='Normal Entropy'),
                mpatches.Patch(color=P['crimson'], label='High Entropy — Suspicious'),
                Line2D([0], [0], color=P['amber'],  linewidth=1.8,
                       linestyle='--', label=f'Detection Threshold ({threshold})'),
            ]
            ax.legend(handles=legend_handles, loc='lower right',
                      framealpha=0.95, fontsize=8.5)

            n_high = sum(1 for r in results if r.get('high_entropy'))
            _section_title(ax,
                           'File Entropy Analysis',
                           f'{n_high} of {n} files exceed the {threshold} threshold')

            # Compact spacing
            fig.tight_layout(pad=1.4)
            out = os.path.join(self.output_dir, output_filename)
            plt.savefig(out)
            plt.close()
            print(f'[OK] Entropy histogram: {out}')
            return out
        except Exception as e:
            print(f'[ERR] Entropy histogram: {e}')
            import traceback; traceback.print_exc()
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # FIGURE 3 — Forensic Timeline (two-panel, compact)
    # ─────────────────────────────────────────────────────────────────────────
    def generate_timeline_chart(self, metadata_results,
                                output_filename='timeline_chart.png'):
        try:
            from datetime import datetime
            import matplotlib.dates as mdates

            # ── Collect data ──────────────────────────────────────────────
            fs_data  = []
            gap_data = []

            for r in metadata_results:
                fs_ts = r.get('fs_timestamps', {})
                if not fs_ts or 'created' not in fs_ts:
                    continue
                created  = fs_ts.get('created')
                modified = fs_ts.get('modified')
                fname    = r['filename'][:36]
                status   = r.get('status', 'normal')
                impossible = (created and modified and created > modified)

                fs_data.append({
                    'filename':    fname,
                    'created':     created,
                    'modified':    modified,
                    'suspicious':  status == 'suspicious',
                    'impossible':  impossible,
                })

                for ind in r.get('suspicious_indicators', []):
                    if 'differs from file system by' in ind.lower():
                        try:
                            days = int(''.join(filter(str.isdigit, ind)))
                            if days > 1:
                                gap_data.append({
                                    'filename':  fname,
                                    'days_gap':  days,
                                    'suspicious': status == 'suspicious',
                                })
                        except ValueError:
                            pass
                        break

            if not fs_data:
                print('[WARN] No timeline data')
                return None

            has_gaps = len(gap_data) > 0
            n_fs     = len(fs_data)

            # ── Figure layout ─────────────────────────────────────────────
            # Panel 1 height: 0.38 per file, capped at 8.5 inches
            p1_h = min(8.5, max(3.5, n_fs * 0.38))
            p2_h = min(4.0, max(2.0, len(gap_data) * 0.42 + 1.2)) if has_gaps else 0
            total_h = p1_h + (p2_h + 0.8 if has_gaps else 0) + 1.2

            fig = plt.figure(figsize=(13, total_h))
            fig.suptitle('Forensic Timeline Analysis',
                         fontsize=13, fontweight='bold',
                         color=P['navy'], y=1.0 - 0.3 / total_h)

            if has_gaps:
                gs = gridspec.GridSpec(
                    2, 1, figure=fig,
                    height_ratios=[p1_h, p2_h],
                    hspace=0.55,
                    left=0.22, right=0.96,
                    top=1.0 - 0.6 / total_h,
                    bottom=0.5 / total_h
                )
                ax1 = fig.add_subplot(gs[0])
                ax2 = fig.add_subplot(gs[1])
            else:
                gs = gridspec.GridSpec(
                    1, 1, figure=fig,
                    left=0.22, right=0.96,
                    top=1.0 - 0.6 / total_h,
                    bottom=0.5 / total_h
                )
                ax1 = fig.add_subplot(gs[0])
                ax2 = None

            # ── Panel 1: Filesystem timestamps ────────────────────────────
            ax1.set_facecolor(P['white'])
            _navy_spine(ax1)

            # Sort by created date
            fs_data.sort(key=lambda x: x['created'] if x['created'] else
                         datetime(2000, 1, 1))
            y_pos = np.arange(len(fs_data))

            for i, d in enumerate(fs_data):
                created  = d['created']
                modified = d['modified']
                if not created:
                    continue

                same = (modified and
                        abs((modified - created).total_seconds()) < 2)

                # Line colour
                if d['impossible']:
                    lcol = P['crimson']
                elif d['suspicious']:
                    lcol = P['amber']
                else:
                    lcol = P['teal']

                # Span line (only if timestamps differ)
                if modified and not same:
                    ax1.plot([created, modified], [i, i],
                             color=lcol, linewidth=2.5,
                             alpha=0.6, solid_capstyle='round', zorder=2)

                # Created marker
                ax1.scatter([created], [i],
                            color=P['green_mid'], s=50, zorder=4,
                            marker='o', edgecolors=P['green'],
                            linewidths=1.2)

                # Modified (only if different)
                if modified and not same:
                    ax1.scatter([modified], [i],
                                color=P['amber_mid'], s=50, zorder=4,
                                marker='D', edgecolors=P['amber'],
                                linewidths=1.2)

                # Flag impossible timestamp
                if d['impossible']:
                    ax1.annotate(
                        ' Created > Modified',
                        xy=(created, i),
                        xytext=(5, 0), textcoords='offset points',
                        fontsize=7, color=P['crimson'],
                        fontweight='bold', va='center'
                    )

                # Subtle row stripe for suspicious
                if d['suspicious'] or d['impossible']:
                    ax1.axhspan(i - 0.45, i + 0.45,
                                color=P['crimson_light'],
                                alpha=0.25, zorder=0)

            ax1.set_yticks(y_pos)
            ax1.set_yticklabels([d['filename'] for d in fs_data], fontsize=8)
            ax1.set_ylim(-0.7, len(fs_data) - 0.3)
            ax1.invert_yaxis()
            ax1.set_xlabel('Date / Time', color=P['slate'], fontsize=9)

            # Smart x-axis format
            all_dates = [d['created'] for d in fs_data if d['created']]
            if all_dates:
                span = (max(all_dates) - min(all_dates)).days
                if span <= 2:
                    ax1.xaxis.set_major_formatter(
                        mdates.DateFormatter('%H:%M'))
                elif span <= 90:
                    ax1.xaxis.set_major_formatter(
                        mdates.DateFormatter('%d %b %Y'))
                else:
                    ax1.xaxis.set_major_formatter(
                        mdates.DateFormatter('%b %Y'))
            plt.setp(ax1.xaxis.get_majorticklabels(),
                     rotation=25, ha='right', fontsize=8)
            ax1.grid(axis='x', linestyle='--', alpha=0.4)

            # Count anomalies for subtitle
            n_anom = sum(1 for d in fs_data if d['suspicious'] or d['impossible'])
            _section_title(ax1,
                           'Panel 1 — File System Timestamps',
                           f'Creation & modification times  |  '
                           f'{n_anom} file(s) with timestamp anomalies')

            # Legend
            leg = [
                Line2D([0], [0], marker='o', color='w',
                       markerfacecolor=P['green_mid'], markersize=8,
                       markeredgecolor=P['green'], label='Created'),
                Line2D([0], [0], marker='D', color='w',
                       markerfacecolor=P['amber_mid'], markersize=8,
                       markeredgecolor=P['amber'], label='Modified'),
                mpatches.Patch(color=P['teal'],   alpha=0.7, label='Normal file'),
                mpatches.Patch(color=P['amber'],  alpha=0.7, label='Suspicious file'),
                mpatches.Patch(color=P['crimson'],alpha=0.7,
                               label='Impossible timestamp'),
            ]
            ax1.legend(handles=leg, loc='lower right', fontsize=7.5,
                       framealpha=0.95)

            # ── Panel 2: Metadata timestamp discrepancy ───────────────────
            if ax2 is not None and gap_data:
                ax2.set_facecolor(P['white'])
                _navy_spine(ax2)

                gap_data.sort(key=lambda x: x['days_gap'], reverse=True)
                g_labels = [d['filename'] for d in gap_data]
                g_vals   = [d['days_gap'] for d in gap_data]
                g_cols   = [P['crimson'] if d['suspicious'] else P['amber_mid']
                            for d in gap_data]
                g_pos    = np.arange(len(gap_data))

                bars = ax2.barh(g_pos, g_vals, color=g_cols,
                                height=0.58, edgecolor=P['white'],
                                linewidth=0.6, alpha=0.88)

                # Value labels
                mx = max(g_vals) if g_vals else 1
                for bar, val in zip(bars, g_vals):
                    yrs = val / 365.25
                    ax2.text(bar.get_width() + mx * 0.01,
                             bar.get_y() + bar.get_height() / 2,
                             f'{val:,} days  ({yrs:.1f} yrs)',
                             va='center', fontsize=7.5, color=P['text'])

                # Reference lines
                for days, lbl, col in [
                    (365,  '1 yr',  P['text_muted']),
                    (1825, '5 yrs', P['slate']),
                    (3650, '10 yrs', P['navy_mid']),
                ]:
                    if days < mx * 1.3:
                        ax2.axvline(days, color=col, linestyle=':',
                                    linewidth=1.2, alpha=0.8)
                        ax2.text(days, len(gap_data) - 0.3, lbl,
                                 fontsize=7, color=col, ha='center',
                                 va='bottom', style='italic')

                ax2.set_yticks(g_pos)
                ax2.set_yticklabels(g_labels, fontsize=8)
                ax2.invert_yaxis()
                ax2.set_xlabel(
                    'Discrepancy (days) between embedded metadata '
                    'timestamp and file system timestamp',
                    color=P['slate'], fontsize=9)
                ax2.set_xlim(0, mx * 1.35)
                ax2.grid(axis='x', linestyle='--', alpha=0.4)

                _section_title(ax2,
                               'Panel 2 — Metadata Timestamp Discrepancy',
                               'Embedded document date vs actual file system date')

                leg2 = [
                    mpatches.Patch(color=P['crimson'],  alpha=0.88,
                                   label='Suspicious file'),
                    mpatches.Patch(color=P['amber_mid'],alpha=0.88,
                                   label='Normal / low-risk file'),
                ]
                ax2.legend(handles=leg2, loc='lower right',
                           fontsize=7.5, framealpha=0.95)

            out = os.path.join(self.output_dir, output_filename)
            plt.savefig(out)
            plt.close()
            print(f'[OK] Timeline chart: {out}')
            return out

        except Exception as e:
            print(f'[ERR] Timeline chart: {e}')
            import traceback; traceback.print_exc()
            return None

    # ─────────────────────────────────────────────────────────────────────────
    # Generate all
    # ─────────────────────────────────────────────────────────────────────────
    def generate_all_visualizations(self, signature_results, entropy_results,
                                    hash_results, metadata_results):
        print('\n' + '='*60)
        print('GENERATING VISUALIZATIONS')
        print('='*60)
        graphs = {}

        p = self.generate_detection_summary(
            signature_results, entropy_results,
            hash_results, metadata_results)
        if p: graphs['summary'] = p

        p = self.generate_entropy_histogram(entropy_results)
        if p: graphs['entropy'] = p

        p = self.generate_timeline_chart(metadata_results)
        if p: graphs['timeline'] = p

        print('='*60)
        print(f'[OK] {len(graphs)} visualizations generated')
        print('='*60)
        return graphs