"""
PDF Report Generator Module — Professional Redesign
Creates comprehensive forensic analysis reports with a refined,
professional appearance suitable for academic and legal submission.

Design language:
  - Primary:   #0f2d4a  (deep navy)
  - Accent:    #1a6b8a  (teal)
  - Highlight: #e8f4f8  (light teal wash)
  - Warning:   #7a3b00  (dark amber — avoids harsh red)
  - Danger:    #8b1a1a  (deep crimson — reserved for CRITICAL only)
  - Success:   #1a5c2e  (forest green)
  - Neutral:   #4a5568  (slate)
  - Border:    #cbd5e0  (light grey)
"""

from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, PageBreak, Image, KeepTogether, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus.flowables import Flowable
from reportlab.pdfgen import canvas as rl_canvas
from datetime import datetime
from pathlib import Path
import os

# ── Colour palette ────────────────────────────────────────────────────────────
C = {
    'navy':        colors.HexColor('#0f2d4a'),
    'navy_mid':    colors.HexColor('#1a4a6e'),
    'teal':        colors.HexColor('#1a6b8a'),
    'teal_light':  colors.HexColor('#e8f4f8'),
    'teal_mid':    colors.HexColor('#b8dce8'),
    'amber':       colors.HexColor('#7a3b00'),
    'amber_light': colors.HexColor('#fef3e2'),
    'amber_mid':   colors.HexColor('#f6d5a0'),
    'crimson':     colors.HexColor('#8b1a1a'),
    'crimson_light': colors.HexColor('#fdf0f0'),
    'green':       colors.HexColor('#1a5c2e'),
    'green_light': colors.HexColor('#edf7f0'),
    'green_mid':   colors.HexColor('#b8dfc5'),
    'slate':       colors.HexColor('#4a5568'),
    'slate_light': colors.HexColor('#f7f8fa'),
    'border':      colors.HexColor('#cbd5e0'),
    'border_light':colors.HexColor('#e8ecf0'),
    'white':       colors.white,
    'black':       colors.black,
    'text':        colors.HexColor('#1a202c'),
    'text_muted':  colors.HexColor('#718096'),
}

# ── Risk level mappings ───────────────────────────────────────────────────────
RISK = {
    'highly_suspicious': {
        'label': 'HIGHLY SUSPICIOUS',
        'marker': '[!!]',
        'fg':  C['crimson'],
        'bg':  C['crimson_light'],
        'border': C['crimson'],
    },
    'suspicious': {
        'label': 'SUSPICIOUS',
        'marker': '[!]',
        'fg':  C['amber'],
        'bg':  C['amber_light'],
        'border': C['amber'],
    },
    'low_risk': {
        'label': 'LOW RISK',
        'marker': '[i]',
        'fg':  C['teal'],
        'bg':  C['teal_light'],
        'border': C['teal'],
    },
    'normal': {
        'label': 'NORMAL',
        'marker': '[ok]',
        'fg':  C['green'],
        'bg':  C['green_light'],
        'border': C['green'],
    },
}

SEV_FG = {
    'critical':    C['crimson'],
    'high':        C['amber'],
    'medium-high': C['amber'],
    'medium':      C['slate'],
    'low':         C['slate'],
    'info':        C['text_muted'],
}


# ── Page template with running header + footer ────────────────────────────────
class _HeaderFooterCanvas(rl_canvas.Canvas):
    """Adds running header and page-numbered footer to every page."""

    def __init__(self, *args, **kwargs):
        rl_canvas.Canvas.__init__(self, *args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for i, state in enumerate(self._saved_page_states):
            self.__dict__.update(state)
            if i > 0:          # skip cover page header/footer
                self._draw_header()
                self._draw_footer(i + 1, num_pages)
            rl_canvas.Canvas.showPage(self)
        rl_canvas.Canvas.save(self)

    def _draw_header(self):
        w, h = letter
        self.saveState()
        self.setFillColor(C['navy'])
        self.rect(0.65*inch, h - 0.55*inch, w - 1.3*inch, 0.28*inch, fill=1, stroke=0)
        self.setFillColor(C['white'])
        self.setFont('Helvetica-Bold', 7.5)
        self.drawString(0.72*inch, h - 0.42*inch,
                        'FORENSIC FILE ANALYSIS REPORT  |  CONFIDENTIAL')
        self.setFont('Helvetica', 7.5)
        self.drawRightString(w - 0.65*inch, h - 0.42*inch,
                             'University of Roehampton London')
        self.restoreState()

    def _draw_footer(self, page_num, total_pages):
        w, _ = letter
        self.saveState()
        self.setStrokeColor(C['border'])
        self.setLineWidth(0.5)
        self.line(0.65*inch, 0.55*inch, w - 0.65*inch, 0.55*inch)
        self.setFillColor(C['text_muted'])
        self.setFont('Helvetica', 7.5)
        self.drawString(0.65*inch, 0.38*inch,
                        f'Muhammad Awais Ali  |  Supervised by Mastaneh Davis')
        self.drawRightString(w - 0.65*inch, 0.38*inch,
                             f'Page {page_num} of {total_pages}')
        self.restoreState()


# ── Thin horizontal rule ──────────────────────────────────────────────────────
def _rule(width=6.5*inch, thickness=0.5, colour=None):
    return HRFlowable(
        width=width, thickness=thickness,
        color=colour or C['border_light'],
        spaceAfter=6, spaceBefore=6
    )


def _sp(h=0.12):
    return Spacer(1, h*inch)


# ═════════════════════════════════════════════════════════════════════════════
class ReportGenerator:
    """Generates professional PDF forensic analysis reports."""

    def __init__(self, output_dir='reports'):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        self.styles = getSampleStyleSheet()
        self._build_styles()

    # ── Style definitions ─────────────────────────────────────────────────────
    def _build_styles(self):
        S = self.styles

        def add(name, **kw):
            if name not in S:
                parent = kw.pop('parent', S['Normal'])
                S.add(ParagraphStyle(name=name, parent=parent, **kw))

        add('ReportTitle',
            fontSize=28, fontName='Helvetica-Bold',
            textColor=C['white'], alignment=TA_CENTER,
            spaceAfter=6, leading=34)

        add('ReportSubtitle',
            fontSize=13, fontName='Helvetica',
            textColor=C['teal_mid'], alignment=TA_CENTER,
            spaceAfter=4)

        add('CoverMeta',
            fontSize=9, fontName='Helvetica',
            textColor=C['teal_light'], alignment=TA_CENTER,
            spaceAfter=2)

        add('SectionHeader',
            fontSize=14, fontName='Helvetica-Bold',
            textColor=C['navy'], spaceBefore=14, spaceAfter=6)

        add('SubHeader',
            fontSize=11, fontName='Helvetica-Bold',
            textColor=C['teal'], spaceBefore=8, spaceAfter=4)

        add('BodyText',
            fontSize=9, fontName='Helvetica',
            textColor=C['text'], leading=14,
            spaceBefore=2, spaceAfter=4, alignment=TA_JUSTIFY)

        add('SmallText',
            fontSize=8, fontName='Helvetica',
            textColor=C['slate'], leading=12)

        add('Caption',
            fontSize=8, fontName='Helvetica-Oblique',
            textColor=C['text_muted'], alignment=TA_CENTER,
            spaceBefore=2, spaceAfter=8)

        add('Warning',
            fontSize=9, fontName='Helvetica-Bold',
            textColor=C['amber'], leftIndent=6)

        add('Danger',
            fontSize=9, fontName='Helvetica-Bold',
            textColor=C['crimson'], leftIndent=6)

        add('OK',
            fontSize=9, fontName='Helvetica',
            textColor=C['green'])

        add('Muted',
            fontSize=8, fontName='Helvetica',
            textColor=C['text_muted'])

        add('TableHeader',
            fontSize=8.5, fontName='Helvetica-Bold',
            textColor=C['white'])

        add('TableCell',
            fontSize=8, fontName='Helvetica',
            textColor=C['text'], leading=11)

        add('TableCellBold',
            fontSize=8, fontName='Helvetica-Bold',
            textColor=C['navy'], leading=11)

        add('RiskLabel',
            fontSize=8.5, fontName='Helvetica-Bold',
            alignment=TA_CENTER)

        add('ScoreLabel',
            fontSize=18, fontName='Helvetica-Bold',
            alignment=TA_CENTER)

    # ── Table style helpers ───────────────────────────────────────────────────
    def _base_table_style(self, header_bg=None, stripe=True):
        hbg = header_bg or C['navy']
        cmds = [
            ('BACKGROUND',    (0, 0), (-1, 0),  hbg),
            ('TEXTCOLOR',     (0, 0), (-1, 0),  C['white']),
            ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
            ('FONTSIZE',      (0, 0), (-1, 0),  8.5),
            ('BOTTOMPADDING', (0, 0), (-1, 0),  8),
            ('TOPPADDING',    (0, 0), (-1, 0),  8),
            ('FONTSIZE',      (0, 1), (-1, -1), 8),
            ('TOPPADDING',    (0, 1), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 5),
            ('LEFTPADDING',   (0, 0), (-1, -1), 7),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 7),
            ('GRID',          (0, 0), (-1, -1), 0.3, C['border']),
            ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ]
        if stripe:
            cmds.append(
                ('ROWBACKGROUNDS', (0, 1), (-1, -1),
                 [C['white'], C['slate_light']])
            )
        return TableStyle(cmds)

    # ── Section banner ────────────────────────────────────────────────────────
    def _section_banner(self, title, subtitle=''):
        """Navy left-bar section heading."""
        banner_data = [[
            Paragraph(f'<b>{title}</b>',
                      ParagraphStyle('BT', parent=self.styles['Normal'],
                                     fontSize=13, fontName='Helvetica-Bold',
                                     textColor=C['navy'])),
            Paragraph(subtitle,
                      ParagraphStyle('BS', parent=self.styles['Normal'],
                                     fontSize=8.5, textColor=C['text_muted'],
                                     alignment=TA_RIGHT)) if subtitle else Paragraph('', self.styles['Normal'])
        ]]
        t = Table(banner_data, colWidths=[4*inch, 2.6*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), C['teal_light']),
            ('LINEAFTER',     (0, 0), (0, 0),   0, C['teal_light']),
            ('LINEBEFORE',    (0, 0), (0, 0),   4, C['teal']),
            ('TOPPADDING',    (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING',   (0, 0), (-1, -1), 10),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 10),
            ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        return [t, _sp(0.14)]

    # ── Info box ──────────────────────────────────────────────────────────────
    def _info_box(self, text, style='teal'):
        colours = {
            'teal':   (C['teal_light'], C['teal'],   C['teal']),
            'amber':  (C['amber_light'], C['amber'],  C['amber']),
            'crimson':(C['crimson_light'], C['crimson'], C['crimson']),
            'green':  (C['green_light'], C['green'],  C['green']),
        }
        bg, border, fg = colours.get(style, colours['teal'])
        data = [[Paragraph(text, ParagraphStyle(
            'IB', parent=self.styles['Normal'],
            fontSize=8.5, textColor=fg, leading=13))]]
        t = Table(data, colWidths=[6.5*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), bg),
            ('LINEBEFORE',    (0, 0), (0, -1),  3, border),
            ('TOPPADDING',    (0, 0), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
            ('LEFTPADDING',   (0, 0), (-1, -1), 10),
        ]))
        return [t, _sp(0.08)]

    # ── Metadata value formatter (dates → readable form) ─────────────────────
    def _fmt_meta_value(self, key, value):
        """
        Format metadata values for display.
        Normalises the three date formats (PDF D:, ISO-8601, EXIF) into a
        consistent  YYYY-MM-DD  HH:MM:SS  string so embedded timestamps look
        the same as the filesystem timestamp row below them.
        """
        DATE_KEYS = {
            'Created', 'Modified',      # Office / generic
            'CreationDate', 'ModDate',  # PDF
            'DateTime',                 # EXIF
        }
        if key in DATE_KEYS and isinstance(value, str) and value not in ('N/A', ''):
            try:
                raw = value.strip()
                if raw.startswith('D:'):
                    # PDF format: D:20241218141249Z00'00'
                    raw = raw[2:16]
                    dt = datetime.strptime(raw, '%Y%m%d%H%M%S')
                elif 'T' in raw:
                    # ISO 8601: 2013-12-23T23:15:00Z  (Office XML)
                    dt = datetime.fromisoformat(
                        raw.replace('Z', '+00:00')
                    ).replace(tzinfo=None)
                elif len(raw) >= 19 and raw[4] == ':' and raw[7] == ':':
                    # EXIF: 2024:12:18 14:12:49
                    dt = datetime.strptime(raw, '%Y:%m:%d %H:%M:%S')
                else:
                    return str(value)[:80]
                return dt.strftime('%Y-%m-%d  %H:%M:%S')
            except Exception:
                pass
        return str(value)[:80]

    # ═══════════════════════════════════════════════════════════════════════════
    # PUBLIC: generate_pdf_report
    # ═══════════════════════════════════════════════════════════════════════════
    def generate_pdf_report(self, signature_results, entropy_results,
                            hash_results, metadata_results,
                            graph_paths=None, output_filename=None):
        try:
            if output_filename is None:
                ts = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_filename = f'forensic_analysis_report_{ts}.pdf'

            output_path = os.path.join(self.output_dir, output_filename)

            doc = SimpleDocTemplate(
                output_path,
                pagesize=letter,
                rightMargin=0.65*inch,
                leftMargin=0.65*inch,
                topMargin=0.8*inch,
                bottomMargin=0.75*inch,
            )

            story = []

            # Cover
            story.extend(self._cover_page())
            story.append(PageBreak())

            # Executive Summary
            story.extend(self._executive_summary(
                signature_results, entropy_results,
                hash_results, metadata_results))
            story.append(PageBreak())

            # Visual Analysis
            if graph_paths:
                story.extend(self._visual_section(graph_paths))
                story.append(PageBreak())

            # Detection sections
            story.extend(self._signature_section(signature_results))
            story.append(PageBreak())

            story.extend(self._entropy_section(entropy_results))
            story.append(PageBreak())

            story.extend(self._hash_section(hash_results))
            story.append(PageBreak())

            story.extend(self._metadata_section(metadata_results))
            story.append(PageBreak())

            story.extend(self._conclusion_section(
                signature_results, entropy_results,
                hash_results, metadata_results))

            doc.build(story, canvasmaker=_HeaderFooterCanvas)
            print(f'[OK] PDF report generated: {output_path}')
            return output_path

        except Exception as e:
            print(f'[ERROR] generating PDF report: {e}')
            import traceback; traceback.print_exc()
            return None

    # ═══════════════════════════════════════════════════════════════════════════
    # COVER PAGE
    # ═══════════════════════════════════════════════════════════════════════════
    def _cover_page(self):
        content = []

        # ── FIX 1: explicit rowHeights + ALIGN/VALIGN so the title never clips ──
        header_data = [[
            Paragraph('FORENSIC FILE ANALYSIS REPORT',
                      self.styles['ReportTitle']),
        ]]
        header_table = Table(header_data,
                             colWidths=[6.5*inch],
                             rowHeights=[1.2*inch])   # <── explicit height
        header_table.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), C['navy']),
            ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING',    (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
            ('LEFTPADDING',   (0, 0), (-1, -1), 20),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 20),
        ]))
        content.append(header_table)

        # Sub-title strip
        sub_data = [[
            Paragraph('Automated Anti-Forensic Detection &amp; Hidden Data Artifact Analysis',
                      self.styles['ReportSubtitle'])
        ]]
        sub_table = Table(sub_data, colWidths=[6.5*inch])
        sub_table.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), C['teal']),
            ('TOPPADDING',    (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))
        content.append(sub_table)
        content.append(_sp(0.5))

        # Report metadata table
        meta_rows = [
            ['Generated',    datetime.now().strftime('%d %B %Y  at  %H:%M:%S')],
            ['Tool Version', 'Forensic File Analyzer v1.0'],
            ['Student',      'Muhammad Awais Ali'],
            ['Institution',  'University of Roehampton London'],
            ['Supervisor',   'Mastaneh Davis'],
            ['Classification', 'CONFIDENTIAL'],
        ]
        meta_data = []
        for label, value in meta_rows:
            meta_data.append([
                Paragraph(f'<b>{label}</b>',
                          ParagraphStyle('ML', parent=self.styles['Normal'],
                                         fontSize=9, fontName='Helvetica-Bold',
                                         textColor=C['navy'])),
                Paragraph(value,
                          ParagraphStyle('MV', parent=self.styles['Normal'],
                                         fontSize=9, textColor=C['text']))
            ])

        meta_table = Table(meta_data, colWidths=[1.8*inch, 4.0*inch])
        meta_table.setStyle(TableStyle([
            ('ROWBACKGROUNDS', (0, 0), (-1, -1),
             [C['slate_light'], C['white']]),
            ('GRID',          (0, 0), (-1, -1), 0.3, C['border_light']),
            ('TOPPADDING',    (0, 0), (-1, -1), 7),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
            ('LEFTPADDING',   (0, 0), (-1, -1), 10),
            ('LINEAFTER',     (0, 0), (0, -1),  1.5, C['teal']),
            # Highlight classification row
            ('BACKGROUND',    (0, 5), (-1, 5),  C['navy']),
            ('TEXTCOLOR',     (0, 5), (-1, 5),  C['white']),
        ]))
        content.append(meta_table)
        content.append(_sp(0.4))

        # Confidentiality notice
        content.extend(self._info_box(
            '<b>CONFIDENTIAL</b>  —  This report contains digital forensic analysis '
            'results and must be handled in accordance with your organisation\'s data '
            'protection and evidence management policies. Unauthorised disclosure may '
            'prejudice ongoing investigations.', 'amber'))

        return content

    # ═══════════════════════════════════════════════════════════════════════════
    # EXECUTIVE SUMMARY
    # ═══════════════════════════════════════════════════════════════════════════
    def _executive_summary(self, sig, ent, hash_r, meta):
        content = []
        content.extend(self._section_banner(
            'EXECUTIVE SUMMARY',
            f'Generated {datetime.now().strftime("%d %b %Y")}'))

        total   = len(hash_r)
        sig_s   = len([r for r in sig   if r.get('mismatch', False)])
        ent_s   = len([r for r in ent   if r.get('high_entropy', False)])
        meta_s  = len([r for r in meta  if r.get('status') == 'suspicious'])

        seen = {}
        dup_count = 0
        for r in hash_r:
            h = r.get('md5')
            if h in seen:
                dup_count += 1
            seen[h] = True

        total_flags = sig_s + ent_s + dup_count + meta_s

        # Narrative
        content.append(Paragraph(
            f'This forensic examination analysed <b>{total} files</b> using four '
            f'independent detection methods: file signature verification, Shannon entropy '
            f'analysis, cryptographic hash comparison, and metadata inspection. '
            f'The investigation identified a total of <b>{total_flags} suspicious '
            f'indicators</b> distributed across the detection categories detailed below.',
            self.styles['BodyText']))
        content.append(_sp(0.15))

        # Four-column KPI strip
        kpi_data = [[
            self._kpi_cell(str(total),    'Files Analysed', C['navy']),
            self._kpi_cell(str(sig_s),    'Signature\nMismatches',
                           C['crimson'] if sig_s else C['green']),
            self._kpi_cell(str(ent_s),    'High Entropy\nFiles',
                           C['amber'] if ent_s else C['green']),
            self._kpi_cell(str(meta_s),   'Metadata\nAnomalies',
                           C['amber'] if meta_s else C['green']),
        ]]
        kpi_table = Table(kpi_data, colWidths=[1.625*inch]*4, rowHeights=[0.9*inch])
        kpi_table.setStyle(TableStyle([
            ('TOPPADDING',    (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
            ('LEFTPADDING',   (0, 0), (-1, -1), 4),
            ('RIGHTPADDING',  (0, 0), (-1, -1), 4),
        ]))
        content.append(kpi_table)
        content.append(_sp(0.2))

        # Detection summary table
        def status_text(count, pos_label):
            return pos_label if count > 0 else 'Clear'

        rows = [
            ['Detection Method', 'Files Examined', 'Flags Raised', 'Outcome'],
            ['File Signature Analysis', str(total), str(sig_s),
             status_text(sig_s, 'Mismatches Detected')],
            ['Shannon Entropy Analysis', str(total), str(ent_s),
             status_text(ent_s, 'High-Entropy Files')],
            ['Hash / Duplicate Detection', str(total), str(dup_count),
             status_text(dup_count, 'Duplicate Sets Found')],
            ['Metadata Integrity Analysis', str(len(meta)), str(meta_s),
             status_text(meta_s, 'Anomalies Found')],
        ]

        tdata = []
        for i, row in enumerate(rows):
            if i == 0:
                tdata.append([Paragraph(c, self.styles['TableHeader']) for c in row])
            else:
                outcome_val = row[3]
                outcome_col = C['green'] if outcome_val == 'Clear' else C['amber']
                flag_val    = row[2]
                flag_col    = C['green'] if flag_val == '0' else C['crimson']
                tdata.append([
                    Paragraph(row[0], self.styles['TableCell']),
                    Paragraph(row[1], ParagraphStyle('TC_c', parent=self.styles['TableCell'],
                                                      alignment=TA_CENTER)),
                    Paragraph(f'<b>{flag_val}</b>',
                              ParagraphStyle('TC_flag', parent=self.styles['TableCell'],
                                             textColor=flag_col, alignment=TA_CENTER,
                                             fontName='Helvetica-Bold')),
                    Paragraph(outcome_val,
                              ParagraphStyle('TC_out', parent=self.styles['TableCell'],
                                             textColor=outcome_col)),
                ])

        det_table = Table(tdata, colWidths=[2.4*inch, 1.2*inch, 1.1*inch, 1.8*inch])
        det_table.setStyle(self._base_table_style())
        content.append(det_table)
        content.append(_sp(0.2))

        # Key findings bullets
        content.append(Paragraph('<b>Key Findings</b>', self.styles['SubHeader']))
        findings = []
        if sig_s:
            findings.append(f'{sig_s} file(s) carry extensions inconsistent with their '
                            f'actual file type — indicative of deliberate obfuscation.')
        if ent_s:
            findings.append(f'{ent_s} file(s) exhibit entropy values above the 7.5 '
                            f'threshold, consistent with encryption or steganographic embedding.')
        if dup_count:
            findings.append(f'{dup_count} duplicate file(s) were identified via MD5 hash '
                            f'comparison, which may indicate data staging or exfiltration.')
        if meta_s:
            findings.append(f'{meta_s} file(s) present metadata anomalies including '
                            f'timestamp discrepancies, stripped EXIF fields, or author inconsistencies.')
        if not findings:
            findings.append('No suspicious indicators were identified. All examined files '
                            'appear consistent with legitimate activity.')

        for f in findings:
            content.append(Paragraph(
                f'<bullet>&bull;</bullet> {f}',
                ParagraphStyle('BulletItem', parent=self.styles['BodyText'],
                               bulletIndent=0, leftIndent=14)))

        return content

    def _kpi_cell(self, value, label, colour):
        data = [[
            Paragraph(f'<b>{value}</b>',
                      ParagraphStyle('KV', parent=self.styles['Normal'],
                                     fontSize=22, fontName='Helvetica-Bold',
                                     textColor=colour, alignment=TA_CENTER)),
        ], [
            Paragraph(label,
                      ParagraphStyle('KL', parent=self.styles['Normal'],
                                     fontSize=7.5, textColor=C['slate'],
                                     alignment=TA_CENTER, leading=10)),
        ]]
        t = Table(data, colWidths=[1.5*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), C['slate_light']),
            ('BOX',           (0, 0), (-1, -1), 0.5, C['border']),
            ('LINEABOVE',     (0, 0), (-1, 0),  2.5, colour),
            ('TOPPADDING',    (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        return t

    # ═══════════════════════════════════════════════════════════════════════════
    # VISUAL ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════════
    def _visual_section(self, graph_paths):
        content = []
        content.extend(self._section_banner('VISUAL ANALYSIS',
                                            'Graphical representations of detection results'))
        content.extend(self._info_box(
            'The charts below provide a visual overview of the analysis findings. '
            'Detailed analytical observations follow each graphic. All graphs were '
            'generated programmatically from the same data used to produce this report.',
            'teal'))

        chart_specs = [
            ('summary',  'Figure 1  —  Forensic Analysis Summary Dashboard',
             'Distribution of suspicious files across each detection category, '
             'with aggregate statistics.',  6.2*inch, 4.3*inch),
            ('entropy',  'Figure 2  —  File Entropy Distribution',
             'Shannon entropy value per file. Files are sorted with suspicious '
             'entries first. The dashed threshold line at 7.5 marks the boundary '
             'above which files are flagged as potentially encrypted or '
             'steganographically modified.',  6.2*inch, None),
            ('timeline', 'Figure 3  —  Forensic Timeline Analysis',
             'Panel 1: Filesystem creation and modification timestamps per file. '
             'Panel 2: Discrepancy (in days) between embedded document metadata '
             'timestamps and actual filesystem timestamps — a key indicator of '
             'backdating or template-based file generation.',  6.2*inch, None),
        ]

        target_w = 6.2 * inch
        max_h    = 7.2 * inch

        for key, title, observation, w, h_hint in chart_specs:
            if key not in graph_paths or not os.path.exists(graph_paths[key]):
                continue

            try:
                from PIL import Image as PILImage
                with PILImage.open(graph_paths[key]) as pil_img:
                    px_w, px_h = pil_img.size
                native_h = target_w * (px_h / px_w)
                display_h = min(native_h, max_h)
            except Exception:
                display_h = h_hint if h_hint else 4.0 * inch

            img = Image(graph_paths[key], width=target_w, height=display_h)
            img.hAlign = 'CENTER'

            caption = Paragraph(f'<i>{title}</i>', self.styles['Caption'])

            obs_items = self._info_box(
                f'<b>Analytical Observation</b>  —  {observation}', 'teal')

            content.append(Paragraph(f'<b>{title}</b>', self.styles['SubHeader']))
            content.append(_rule())
            content.append(KeepTogether([img, _sp(0.05), caption,
                                         _sp(0.08)] + obs_items))
            content.append(_sp(0.22))

        return content

    # ═══════════════════════════════════════════════════════════════════════════
    # FILE SIGNATURE SECTION
    # ═══════════════════════════════════════════════════════════════════════════
    def _signature_section(self, results):
        content = []
        suspicious = [r for r in results if r.get('mismatch', False)]
        content.extend(self._section_banner(
            'FILE SIGNATURE ANALYSIS',
            f'{len(suspicious)} mismatch(es) detected of {len(results)} files'))

        content.extend(self._info_box(
            'File signature analysis compares the magic bytes (file header) of each '
            'file against its declared extension. A discrepancy indicates that the file '
            'type has been deliberately obfuscated — a common anti-forensic technique '
            'used to conceal malicious payloads or evidence.', 'teal'))

        if suspicious:
            content.extend(self._info_box(
                f'<b>{len(suspicious)} file(s) detected with extension-content mismatches.</b>  '
                f'Each entry below identifies the declared extension and the type determined '
                f'by header inspection.', 'amber'))

            rows = [['Filename', 'Ext.', 'Actual Type (Header)', 'File Path']]
            for r in suspicious:
                raw_path = r.get('filepath', 'N/A')
                parts    = Path(raw_path).parts
                short_path = str(Path(*parts[-2:])) if len(parts) >= 2 else raw_path
                rows.append([
                    Paragraph(r.get('filename', 'N/A'), self.styles['TableCell']),
                    Paragraph(r.get('extension', 'N/A'),
                              ParagraphStyle('tc_c', parent=self.styles['TableCell'],
                                             alignment=TA_CENTER)),
                    Paragraph(r.get('detected_type', 'N/A')[:40],
                              ParagraphStyle('tc_warn', parent=self.styles['TableCell'],
                                             textColor=C['amber'])),
                    Paragraph(short_path,
                              self.styles['SmallText']),
                ])

            t = Table(rows, colWidths=[1.8*inch, 0.65*inch, 1.9*inch, 2.15*inch])
            t.setStyle(self._base_table_style(header_bg=C['navy_mid']))
            content.append(t)
        else:
            content.extend(self._info_box(
                'No file signature mismatches detected. All files present headers '
                'consistent with their declared extensions.', 'green'))

        return content

    # ═══════════════════════════════════════════════════════════════════════════
    # ENTROPY SECTION
    # ═══════════════════════════════════════════════════════════════════════════
    def _entropy_section(self, results):
        content = []
        high = [r for r in results if r.get('high_entropy', False)]
        content.extend(self._section_banner(
            'ENTROPY ANALYSIS',
            f'{len(high)} high-entropy file(s) of {len(results)} examined'))

        content.extend(self._info_box(
            'Shannon entropy quantifies the randomness of byte distribution within a '
            'file. Legitimate document files typically score between 4.0 and 6.5. '
            'Values exceeding 7.5 are consistent with encryption, strong compression, '
            'or steganographic modification — all recognised anti-forensic techniques.', 'teal'))

        if high:
            content.extend(self._info_box(
                f'<b>{len(high)} file(s) exceed the 7.5 detection threshold.</b>  '
                f'These files warrant further examination to determine whether high '
                f'entropy is attributable to encryption, steganography, or benign '
                f'compression.', 'amber'))

            rows = [['Filename', 'Entropy Value', 'Classification', 'Assessment']]
            for r in high:
                ent_val = f"{r.get('entropy', 0):.4f}"
                rows.append([
                    Paragraph(r.get('filename', 'N/A'), self.styles['TableCell']),
                    Paragraph(ent_val,
                              ParagraphStyle('tc_ent', parent=self.styles['TableCell'],
                                             alignment=TA_CENTER, fontName='Helvetica-Bold',
                                             textColor=C['amber'])),
                    Paragraph(r.get('category', 'N/A'), self.styles['TableCell']),
                    Paragraph('Requires Investigation',
                              ParagraphStyle('tc_flag', parent=self.styles['TableCell'],
                                             textColor=C['amber'])),
                ])

            t = Table(rows, colWidths=[2.3*inch, 1.1*inch, 2.0*inch, 1.1*inch])
            t.setStyle(self._base_table_style(header_bg=C['navy_mid']))
            content.append(t)
        else:
            content.extend(self._info_box(
                'All files returned entropy values within the normal range. '
                'No encryption or steganographic modification indicators detected.', 'green'))

        return content

    # ═══════════════════════════════════════════════════════════════════════════
    # HASH / DUPLICATE SECTION
    # ═══════════════════════════════════════════════════════════════════════════
    def _hash_section(self, results):
        content = []

        # ── Duplicate detection (unchanged) ──────────────────────────────
        hash_map = {}
        for r in results:
            md5 = r.get('md5')
            if md5:
                hash_map.setdefault(md5, []).append(r)
        duplicates = {k: v for k, v in hash_map.items() if len(v) > 1}

        # ── VirusTotal counts (new) ───────────────────────────────────────
        vt_checked    = [r for r in results
                         if r.get('vt_verdict') not in (None, 'SKIPPED', 'ERROR')]
        vt_malicious  = [r for r in vt_checked if r.get('vt_verdict') == 'MALICIOUS']
        vt_suspicious = [r for r in vt_checked if r.get('vt_verdict') == 'SUSPICIOUS']
        vt_was_run    = len(vt_checked) > 0

        # ── Section banner ────────────────────────────────────────────────
        subtitle = (f'{len(duplicates)} duplicate set(s) identified'
                    + (f'  ·  {len(vt_malicious)} VT malicious' if vt_was_run else ''))
        content.extend(self._section_banner(
            'HASH VERIFICATION & DUPLICATE DETECTION', subtitle))

        content.extend(self._info_box(
            'Cryptographic hash values (MD5, SHA-1, and SHA-256) serve as unique '
            'file fingerprints. Files sharing an identical hash are byte-for-byte '
            'identical regardless of filename or location. Each file is additionally '
            'cross-referenced against the VirusTotal threat intelligence database '
            'where the API key is configured.',
            'teal'))

        # ═════════════════════════════════════════════════════════════════
        # PART A — THREAT INTELLIGENCE (VirusTotal)
        # ═════════════════════════════════════════════════════════════════
        if vt_was_run:
            content.append(Paragraph(
                '<b>Threat Intelligence — VirusTotal API Results</b>',
                self.styles['SubHeader']))

            # VT summary KPI row
            vt_clean   = len([r for r in vt_checked if r.get('vt_verdict') == 'CLEAN'])
            vt_unknown = len([r for r in vt_checked if r.get('vt_verdict') == 'UNKNOWN'])

            vt_kpi_data = [[
                self._kpi_cell(str(len(vt_checked)),    'Files\nChecked',   C['navy']),
                self._kpi_cell(str(len(vt_malicious)),  'Malicious',
                               C['crimson'] if vt_malicious else C['green']),
                self._kpi_cell(str(len(vt_suspicious)), 'Suspicious',
                               C['amber'] if vt_suspicious else C['green']),
                self._kpi_cell(str(vt_clean),           'Clean',            C['green']),
                self._kpi_cell(str(vt_unknown),         'Unknown',          C['slate']),
            ]]
            vt_kpi_table = Table(vt_kpi_data,
                                 colWidths=[1.3*inch]*5,
                                 rowHeights=[0.85*inch])
            vt_kpi_table.setStyle(TableStyle([
                ('TOPPADDING',    (0, 0), (-1, -1), 0),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
                ('LEFTPADDING',   (0, 0), (-1, -1), 3),
                ('RIGHTPADDING',  (0, 0), (-1, -1), 3),
            ]))
            content.append(vt_kpi_table)
            content.append(_sp(0.15))

            # ── Malicious files — highlighted block ───────────────────────
            if vt_malicious:
                content.extend(self._info_box(
                    f'<b>⚠  {len(vt_malicious)} file(s) confirmed MALICIOUS by '
                    f'VirusTotal.</b>  These files were flagged by multiple antivirus '
                    f'engines and require immediate investigation.',
                    'crimson'))

                mal_rows = [[
                    Paragraph('<b>Filename</b>',         self.styles['TableHeader']),
                    Paragraph('<b>SHA-256</b>',          self.styles['TableHeader']),
                    Paragraph('<b>Detection Ratio</b>',  self.styles['TableHeader']),
                    Paragraph('<b>Threat Name(s)</b>',   self.styles['TableHeader']),
                    Paragraph('<b>Last Analysed</b>',    self.styles['TableHeader']),
                ]]
                for r in vt_malicious:
                    sha = r.get('sha256', 'N/A')
                    sha_display = f'{sha[:20]}…' if len(sha) > 20 else sha
                    threats = ', '.join(r.get('vt_threat_names', [])[:3]) or '—'
                    mal_rows.append([
                        Paragraph(r.get('filename', 'N/A'),
                                  self.styles['TableCell']),
                        Paragraph(sha_display,
                                  ParagraphStyle('mono', parent=self.styles['SmallText'],
                                                 textColor=C['crimson'])),
                        Paragraph(f'<b>{r.get("vt_detection_ratio","N/A")}</b>',
                                  ParagraphStyle('ratio', parent=self.styles['TableCell'],
                                                 textColor=C['crimson'],
                                                 fontName='Helvetica-Bold',
                                                 alignment=TA_CENTER)),
                        Paragraph(threats,
                                  ParagraphStyle('thr', parent=self.styles['SmallText'],
                                                 textColor=C['amber'])),
                        Paragraph(r.get('vt_last_analysis', 'N/A'),
                                  self.styles['SmallText']),
                    ])
                mal_t = Table(mal_rows,
                              colWidths=[1.3*inch, 1.4*inch, 0.9*inch,
                                         1.7*inch, 1.2*inch])
                mal_t.setStyle(TableStyle([
                    ('BACKGROUND',    (0, 0), (-1, 0),  C['crimson']),
                    ('TEXTCOLOR',     (0, 0), (-1, 0),  C['white']),
                    ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
                    ('FONTSIZE',      (0, 0), (-1, -1), 7.5),
                    ('GRID',          (0, 0), (-1, -1), 0.3, C['border_light']),
                    ('ROWBACKGROUNDS',(0, 1), (-1, -1),
                     [C['crimson_light'], C['white']]),
                    ('TOPPADDING',    (0, 0), (-1, -1), 5),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                    ('LEFTPADDING',   (0, 0), (-1, -1), 6),
                    ('LINEBEFORE',    (0, 0), (0, -1),  2, C['crimson']),
                    ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
                ]))
                content.append(mal_t)
                content.append(_sp(0.12))

            # ── Suspicious files ──────────────────────────────────────────
            if vt_suspicious:
                content.extend(self._info_box(
                    f'<b>{len(vt_suspicious)} file(s) flagged as SUSPICIOUS</b>  '
                    f'(1–2 engine detections). Manual review is recommended.',
                    'amber'))

                sus_rows = [[
                    Paragraph('<b>Filename</b>',        self.styles['TableHeader']),
                    Paragraph('<b>SHA-256</b>',         self.styles['TableHeader']),
                    Paragraph('<b>Detection Ratio</b>', self.styles['TableHeader']),
                    Paragraph('<b>VT Report</b>',       self.styles['TableHeader']),
                ]]
                for r in vt_suspicious:
                    sha = r.get('sha256', 'N/A')
                    sha_display = f'{sha[:20]}…' if len(sha) > 20 else sha
                    sus_rows.append([
                        Paragraph(r.get('filename', 'N/A'),
                                  self.styles['TableCell']),
                        Paragraph(sha_display, self.styles['SmallText']),
                        Paragraph(r.get('vt_detection_ratio', 'N/A'),
                                  ParagraphStyle('sr', parent=self.styles['TableCell'],
                                                 textColor=C['amber'],
                                                 alignment=TA_CENTER)),
                        Paragraph(r.get('vt_link', 'N/A'),
                                  ParagraphStyle('lnk', parent=self.styles['SmallText'],
                                                 textColor=C['teal'])),
                    ])
                sus_t = Table(sus_rows,
                              colWidths=[1.5*inch, 1.5*inch, 0.9*inch, 2.6*inch])
                sus_t.setStyle(self._base_table_style(header_bg=C['amber']))
                content.append(sus_t)
                content.append(_sp(0.12))

            # ── Complete VT results table ──────────────────────────────────
            content.append(Paragraph(
                '<b>Complete VirusTotal Results</b>',
                ParagraphStyle('VTHdr', parent=self.styles['Normal'],
                               fontSize=9, fontName='Helvetica-Bold',
                               textColor=C['navy'],
                               spaceBefore=6, spaceAfter=4)))

            all_vt_rows = [[
                Paragraph('<b>Filename</b>',    self.styles['TableHeader']),
                Paragraph('<b>MD5</b>',         self.styles['TableHeader']),
                Paragraph('<b>Verdict</b>',     self.styles['TableHeader']),
                Paragraph('<b>Ratio</b>',       self.styles['TableHeader']),
                Paragraph('<b>Threats</b>',     self.styles['TableHeader']),
            ]]
            for r in results:
                verdict = r.get('vt_verdict', 'SKIPPED')
                if verdict == 'SKIPPED':
                    continue
                v_colour = {
                    'MALICIOUS':  C['crimson'],
                    'SUSPICIOUS': C['amber'],
                    'CLEAN':      C['green'],
                    'UNKNOWN':    C['slate'],
                    'ERROR':      C['slate'],
                }.get(verdict, C['slate'])
                md5_short = str(r.get('md5', 'N/A'))[:16] + '…'
                threats   = ', '.join(r.get('vt_threat_names', [])[:2]) or '—'
                all_vt_rows.append([
                    Paragraph(r.get('filename', 'N/A'), self.styles['TableCell']),
                    Paragraph(md5_short, self.styles['SmallText']),
                    Paragraph(f'<b>{verdict}</b>',
                              ParagraphStyle('vv', parent=self.styles['TableCell'],
                                             textColor=v_colour,
                                             fontName='Helvetica-Bold',
                                             alignment=TA_CENTER)),
                    Paragraph(r.get('vt_detection_ratio', 'N/A'),
                              ParagraphStyle('vr', parent=self.styles['TableCell'],
                                             alignment=TA_CENTER)),
                    Paragraph(threats,
                              ParagraphStyle('vt', parent=self.styles['SmallText'],
                                             textColor=C['amber']
                                             if threats != '—' else C['text_muted'])),
                ])

            if len(all_vt_rows) > 1:
                avt = Table(all_vt_rows,
                            colWidths=[1.6*inch, 1.2*inch, 0.85*inch,
                                       0.7*inch, 2.15*inch])
                avt.setStyle(self._base_table_style(header_bg=C['navy_mid']))
                content.append(avt)
                content.append(_sp(0.18))

        else:
            # VT was not run — brief note
            content.extend(self._info_box(
                'VirusTotal threat intelligence was not enabled for this analysis. '
                'To activate, set the <b>VIRUSTOTAL_API_KEY</b> environment variable '
                'and enable the option in the GUI before running.',
                'teal'))

        # ═════════════════════════════════════════════════════════════════
        # PART B — DUPLICATE DETECTION (unchanged structure, VT verdict added)
        # ═════════════════════════════════════════════════════════════════
        content.append(Paragraph(
            '<b>Duplicate File Detection</b>',
            self.styles['SubHeader']))

        if duplicates:
            content.extend(self._info_box(
                f'<b>{len(duplicates)} duplicate set(s) identified.</b>  '
                f'Files sharing an identical MD5 hash are byte-for-byte identical '
                f'regardless of filename or location. This may indicate data staging, '
                f'unauthorised copying, or exfiltration activity.',
                'amber'))
            content.append(_sp(0.08))

            for idx, (hash_val, files) in enumerate(duplicates.items(), 1):
                # Set header — unchanged
                hdr_data = [[
                    Paragraph(f'<b>Duplicate Set {idx}</b>',
                              ParagraphStyle('DSH', parent=self.styles['Normal'],
                                             fontSize=9, fontName='Helvetica-Bold',
                                             textColor=C['white'])),
                    Paragraph(f'MD5: {hash_val[:32]}…',
                              ParagraphStyle('DSH2', parent=self.styles['Normal'],
                                             fontSize=7.5, textColor=C['teal_mid'],
                                             fontName='Helvetica-Oblique')),
                    Paragraph(f'{len(files)} identical files',
                              ParagraphStyle('DSH3', parent=self.styles['Normal'],
                                             fontSize=8.5, textColor=C['amber_mid'],
                                             alignment=TA_RIGHT)),
                ]]
                hdr_t = Table(hdr_data, colWidths=[1.3*inch, 3.5*inch, 1.7*inch])
                hdr_t.setStyle(TableStyle([
                    ('BACKGROUND',    (0, 0), (-1, -1), C['navy']),
                    ('TOPPADDING',    (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                    ('LEFTPADDING',   (0, 0), (-1, -1), 8),
                    ('RIGHTPADDING',  (0, 0), (-1, -1), 8),
                    ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
                ]))
                content.append(hdr_t)

                # File rows — VT Verdict column added
                file_rows = [['Filename', 'Size', 'VT Verdict', 'Path']]
                for f in files:
                    raw_fp   = f.get('filepath', 'N/A')
                    fp_parts = Path(raw_fp).parts
                    short_fp = str(Path(*fp_parts[-2:])) if len(fp_parts) >= 2 else raw_fp
                    verdict  = f.get('vt_verdict', 'SKIPPED')
                    v_col    = {
                        'MALICIOUS':  C['crimson'],
                        'SUSPICIOUS': C['amber'],
                        'CLEAN':      C['green'],
                    }.get(verdict, C['text_muted'])
                    file_rows.append([
                        Paragraph(f['filename'], self.styles['TableCell']),
                        Paragraph(f'{f.get("size_bytes", 0):,} bytes',
                                  ParagraphStyle('tc_sz',
                                                 parent=self.styles['TableCell'],
                                                 alignment=TA_RIGHT)),
                        Paragraph(verdict,
                                  ParagraphStyle('tc_vt',
                                                 parent=self.styles['TableCell'],
                                                 textColor=v_col,
                                                 fontName='Helvetica-Bold',
                                                 alignment=TA_CENTER)),
                        Paragraph(short_fp, self.styles['SmallText']),
                    ])
                ft = Table(file_rows,
                           colWidths=[1.8*inch, 0.85*inch, 0.85*inch, 3.0*inch])
                ft.setStyle(self._base_table_style(header_bg=C['slate']))
                content.append(ft)
                content.append(_sp(0.15))

        else:
            content.extend(self._info_box(
                'No duplicate files detected. Every file in the analysis set '
                'produces a unique cryptographic hash value.',
                'green'))

        return content



    # ═══════════════════════════════════════════════════════════════════════════
    # METADATA SECTION (with ForensicIntelligence)
    # ═══════════════════════════════════════════════════════════════════════════
    def _metadata_section(self, results):
        try:
            from forensic_intelligence import ForensicIntelligence
            intelligence = ForensicIntelligence()
        except ImportError:
            intelligence = None

        content = []
        content.extend(self._section_banner(
            'METADATA INTEGRITY ANALYSIS',
            f'{len(results)} files assessed'))

        content.extend(self._info_box(
            'Metadata analysis examines embedded document properties (author, '
            'creation/modification dates, application), EXIF image data, PDF '
            'metadata fields, and file system timestamps. Each file is scored '
            'on a 0–100 scale using a weighted intelligence model that accounts '
            'for anomaly severity, contextual plausibility, and cross-indicator '
            'correlation.', 'teal'))

        # ── Summary KPI row ────────────────────────────────────────────────
        def _get_level(r):
            if intelligence:
                a = intelligence.analyze_anomalies(
                    r.get('suspicious_indicators', []),
                    r.get('metadata', {}),
                    r.get('file_type', 'unknown'))
                return a['risk_level'], a['risk_score']
            return ('suspicious' if r.get('status') == 'suspicious'
                    else 'normal'), 0.0

        risk_counts = {'normal': 0, 'low_risk': 0,
                       'suspicious': 0, 'highly_suspicious': 0}
        analyzed = []
        for r in results:
            lvl, score = _get_level(r)
            risk_counts[lvl] += 1
            analyzed.append((r, lvl, score))

        # Sort highest risk first
        order = {'highly_suspicious': 0, 'suspicious': 1,
                 'low_risk': 2, 'normal': 3}
        analyzed.sort(key=lambda x: order.get(x[1], 4))

        # Summary bar
        sum_data = [[
            Paragraph(f'<b>{len(results)}</b><br/><font size=7>Total</font>',
                      ParagraphStyle('S0', parent=self.styles['Normal'],
                                     fontSize=14, fontName='Helvetica-Bold',
                                     textColor=C['navy'], alignment=TA_CENTER)),
            Paragraph(f'<b>{risk_counts["highly_suspicious"]}</b><br/>'
                      f'<font size=7>High Risk</font>',
                      ParagraphStyle('S1', parent=self.styles['Normal'],
                                     fontSize=14, fontName='Helvetica-Bold',
                                     textColor=C['crimson'], alignment=TA_CENTER)),
            Paragraph(f'<b>{risk_counts["suspicious"]}</b><br/>'
                      f'<font size=7>Suspicious</font>',
                      ParagraphStyle('S2', parent=self.styles['Normal'],
                                     fontSize=14, fontName='Helvetica-Bold',
                                     textColor=C['amber'], alignment=TA_CENTER)),
            Paragraph(f'<b>{risk_counts["low_risk"]}</b><br/>'
                      f'<font size=7>Low Risk</font>',
                      ParagraphStyle('S3', parent=self.styles['Normal'],
                                     fontSize=14, fontName='Helvetica-Bold',
                                     textColor=C['teal'], alignment=TA_CENTER)),
            Paragraph(f'<b>{risk_counts["normal"]}</b><br/>'
                      f'<font size=7>Normal</font>',
                      ParagraphStyle('S4', parent=self.styles['Normal'],
                                     fontSize=14, fontName='Helvetica-Bold',
                                     textColor=C['green'], alignment=TA_CENTER)),
        ]]
        sum_table = Table(sum_data, colWidths=[1.3*inch]*5, rowHeights=[0.65*inch])
        sum_table.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (0, 0),  C['teal_light']),
            ('BACKGROUND',    (1, 0), (1, 0),  C['crimson_light']),
            ('BACKGROUND',    (2, 0), (2, 0),  C['amber_light']),
            ('BACKGROUND',    (3, 0), (3, 0),  C['teal_light']),
            ('BACKGROUND',    (4, 0), (4, 0),  C['green_light']),
            ('BOX',           (0, 0), (-1, -1), 0.3, C['border']),
            ('INNERGRID',     (0, 0), (-1, -1), 0.3, C['border']),
            ('LINEABOVE',     (1, 0), (1, 0),  2.5, C['crimson']),
            ('LINEABOVE',     (2, 0), (2, 0),  2.5, C['amber']),
            ('LINEABOVE',     (3, 0), (3, 0),  2.5, C['teal']),
            ('LINEABOVE',     (4, 0), (4, 0),  2.5, C['green']),
            ('TOPPADDING',    (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ]))
        content.append(sum_table)
        content.append(_sp(0.2))

        # ── Per-file entries ───────────────────────────────────────────────
        for r, lvl, score in analyzed:
            score_int = int(round(score * 100))
            rmap      = RISK[lvl]

            # ── FIX 2: skip ALL normal files — no entry at all ─────────────
            if lvl == 'normal':
                continue

            # ── File header card ──────────────────────────────────────────
            hdr_data = [[
                Paragraph(f'<b>{r["filename"]}</b>',
                          ParagraphStyle('FH', parent=self.styles['Normal'],
                                         fontSize=9.5, fontName='Helvetica-Bold',
                                         textColor=rmap['fg'])),
                Paragraph(f'<b>{rmap["label"]}</b>',
                          ParagraphStyle('Badge', parent=self.styles['Normal'],
                                         fontSize=8.5, textColor=rmap['fg'],
                                         alignment=TA_CENTER,
                                         fontName='Helvetica-Bold')),
                Paragraph(f'<b>{score_int}</b><font size=8> / 100</font>',
                          ParagraphStyle('Score', parent=self.styles['Normal'],
                                         fontSize=15, fontName='Helvetica-Bold',
                                         textColor=rmap['fg'], alignment=TA_CENTER)),
                Paragraph(r.get('file_type', 'unknown').replace('_', ' ').title(),
                          ParagraphStyle('FType', parent=self.styles['Normal'],
                                         fontSize=8, textColor=C['slate'],
                                         alignment=TA_CENTER)),
            ]]
            hdr_t = Table(hdr_data, colWidths=[2.85*inch, 1.5*inch, 1.1*inch, 1.05*inch])
            hdr_t.setStyle(TableStyle([
                ('BACKGROUND',    (0, 0), (-1, -1), rmap['bg']),
                ('LINEABOVE',     (0, 0), (-1, 0),  2, rmap['border']),
                ('LINEBEFORE',    (0, 0), (0, -1),  2, rmap['border']),
                ('LINEBELOW',     (0, 0), (-1, -1), 0.3, C['border_light']),
                ('LINEAFTER',     (-1, 0), (-1, -1), 0.3, C['border_light']),
                ('TOPPADDING',    (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
                ('LEFTPADDING',   (0, 0), (-1, -1), 8),
                ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
                ('LINEAFTER',     (0, 0), (2, -1),  0.3, C['border_light']),
            ]))
            content.append(KeepTogether([hdr_t]))
            content.append(_sp(0.04))

            # ── FIX 4: Embedded metadata table — dates formatted consistently ──
            populated = {k: v for k, v in r.get('metadata', {}).items()
                         if v and v != 'N/A'}
            if populated:
                mrows = [[
                    Paragraph('<b>Metadata Field</b>', self.styles['TableHeader']),
                    Paragraph('<b>Value</b>', self.styles['TableHeader']),
                ]]
                for field, value in populated.items():
                    mrows.append([
                        Paragraph(str(field), self.styles['TableCellBold']),
                        # _fmt_meta_value normalises date strings to YYYY-MM-DD HH:MM:SS
                        Paragraph(self._fmt_meta_value(str(field), value),
                                  self.styles['TableCell']),
                    ])
                mt = Table(mrows, colWidths=[1.6*inch, 4.9*inch])
                mt.setStyle(TableStyle([
                    ('BACKGROUND',    (0, 0), (-1, 0),  C['navy_mid']),
                    ('TEXTCOLOR',     (0, 0), (-1, 0),  C['white']),
                    ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
                    ('FONTSIZE',      (0, 0), (-1, -1), 8),
                    ('GRID',          (0, 0), (-1, -1), 0.3, C['border_light']),
                    ('ROWBACKGROUNDS',(0, 1), (-1, -1),
                     [C['white'], C['teal_light']]),
                    ('LEFTPADDING',   (0, 0), (-1, -1), 7),
                    ('TOPPADDING',    (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LINEBEFORE',    (0, 0), (0, -1),  2, rmap['border']),
                ]))
                content.append(mt)
                content.append(_sp(0.04))

            # ── Filesystem timestamps ──────────────────────────────────────
            fs_ts = r.get('fs_timestamps', {})
            if fs_ts:
                def fmt(ts):
                    if hasattr(ts, 'strftime'):
                        return ts.strftime('%Y-%m-%d  %H:%M:%S')
                    return str(ts).split('.')[0]

                ts_data = [[
                    Paragraph('<b>Created</b>',  self.styles['TableCellBold']),
                    Paragraph(fmt(fs_ts.get('created', 'N/A')), self.styles['TableCell']),
                    Paragraph('<b>Modified</b>', self.styles['TableCellBold']),
                    Paragraph(fmt(fs_ts.get('modified', 'N/A')), self.styles['TableCell']),
                    Paragraph('<b>Accessed</b>', self.styles['TableCellBold']),
                    Paragraph(fmt(fs_ts.get('accessed', 'N/A')), self.styles['TableCell']),
                ]]
                ts_t = Table(ts_data,
                             colWidths=[0.7*inch, 1.45*inch,
                                        0.7*inch, 1.45*inch,
                                        0.7*inch, 1.5*inch])
                ts_t.setStyle(TableStyle([
                    ('BACKGROUND',    (0, 0), (0, 0),  C['slate_light']),
                    ('BACKGROUND',    (2, 0), (2, 0),  C['slate_light']),
                    ('BACKGROUND',    (4, 0), (4, 0),  C['slate_light']),
                    ('FONTSIZE',      (0, 0), (-1, -1), 8),
                    ('GRID',          (0, 0), (-1, -1), 0.3, C['border_light']),
                    ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
                    ('TOPPADDING',    (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LINEBEFORE',    (0, 0), (0, -1),  2, rmap['border']),
                ]))
                content.append(ts_t)
                content.append(_sp(0.04))

            # ── Findings table ─────────────────────────────────────────────
            if intelligence:
                analysis = intelligence.analyze_anomalies(
                    r.get('suspicious_indicators', []),
                    r.get('metadata', {}),
                    r.get('file_type', 'unknown'))
                explanations = [e for e in analysis.get('explanations', [])
                                if e.get('severity') != 'info']
                correlations = [c for c in analysis.get('correlated_findings', [])
                                if c.startswith('[!]') or c.startswith('⚠')]
            else:
                explanations = []
                correlations = []

            if explanations:
                f_rows = [[
                    Paragraph('<b>#</b>',         self.styles['TableHeader']),
                    Paragraph('<b>Finding</b>',   self.styles['TableHeader']),
                    Paragraph('<b>Severity</b>',  self.styles['TableHeader']),
                    Paragraph('<b>Likely Benign Explanation</b>', self.styles['TableHeader']),
                    Paragraph('<b>Possible Threat</b>',          self.styles['TableHeader']),
                ]]
                for i, exp in enumerate(explanations, 1):
                    sev      = exp['severity'].upper()
                    sev_col  = SEV_FG.get(exp['severity'], C['slate'])
                    show_thr = exp['severity'] in ('high', 'critical', 'medium-high', 'medium')
                    f_rows.append([
                        Paragraph(str(i), ParagraphStyle(
                            'FN', parent=self.styles['Normal'],
                            fontSize=8, alignment=TA_CENTER)),
                        Paragraph(exp['finding'], self.styles['TableCell']),
                        Paragraph(f'<b>{sev}</b>',
                                  ParagraphStyle('FS', parent=self.styles['Normal'],
                                                 fontSize=7.5, textColor=sev_col,
                                                 fontName='Helvetica-Bold',
                                                 alignment=TA_CENTER)),
                        Paragraph(exp.get('likely_benign_reason', '—'),
                                  ParagraphStyle('FB', parent=self.styles['TableCell'],
                                                 textColor=C['green'])),
                        Paragraph(exp.get('possible_malicious_reason', '—')
                                  if show_thr else '—',
                                  ParagraphStyle('FM', parent=self.styles['TableCell'],
                                                 textColor=C['crimson'])),
                    ])

                # ── FIX 3: navy_mid header bg + explicit white text ─────────
                ft = Table(f_rows,
                           colWidths=[0.25*inch, 1.85*inch, 0.75*inch,
                                      1.75*inch, 1.9*inch])
                ft.setStyle(TableStyle([
                    ('BACKGROUND',    (0, 0), (-1, 0),  C['navy_mid']),   # dark header
                    ('TEXTCOLOR',     (0, 0), (-1, 0),  C['white']),      # white text
                    ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
                    ('FONTSIZE',      (0, 0), (-1, -1), 8),
                    ('GRID',          (0, 0), (-1, -1), 0.3, C['border_light']),
                    ('ROWBACKGROUNDS',(0, 1), (-1, -1),
                     [C['white'], C['slate_light']]),
                    ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
                    ('LEFTPADDING',   (0, 0), (-1, -1), 5),
                    ('TOPPADDING',    (0, 0), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ('LINEBEFORE',    (0, 0), (0, -1),  2, rmap['border']),
                ]))
                content.append(ft)

            # ── Correlation analysis ───────────────────────────────────────
            if correlations:
                content.append(_sp(0.04))
                content.extend(self._info_box(
                    '<b>Correlation Analysis</b>  —  ' +
                    '  |  '.join(correlations), 'amber'))

            content.append(_sp(0.18))

        return content

    # ═══════════════════════════════════════════════════════════════════════════
    # CONCLUSION
    # ═══════════════════════════════════════════════════════════════════════════
    def _conclusion_section(self, sig, ent, hash_r, meta):
        content = []
        content.extend(self._section_banner(
            'CONCLUSION & RECOMMENDATIONS'))

        sig_s  = len([r for r in sig  if r.get('mismatch', False)])
        ent_s  = len([r for r in ent  if r.get('high_entropy', False)])
        meta_s = len([r for r in meta if r.get('status') == 'suspicious'])
        total  = sig_s + ent_s + meta_s

        if total > 0:
            conclusion = (
                f'This forensic examination identified <b>{total} suspicious indicators</b> '
                f'across the analysed file set. The combination of file signature mismatches, '
                f'elevated entropy values, and metadata anomalies is consistent with the '
                f'deliberate use of anti-forensic techniques including file type obfuscation, '
                f'data concealment, and timestamp manipulation. These findings warrant '
                f'escalation to a full forensic examination.'
            )
            box_style = 'amber'
        else:
            conclusion = (
                'This forensic examination found <b>no significant suspicious indicators</b>. '
                'All examined files present characteristics consistent with legitimate, '
                'unmodified content. No evidence of anti-forensic techniques was identified '
                'during this automated analysis phase.'
            )
            box_style = 'green'

        content.extend(self._info_box(conclusion, box_style))
        content.append(_sp(0.15))

        content.append(Paragraph('<b>Recommended Actions</b>', self.styles['SubHeader']))

        if total > 0:
            recs = [
                ('Priority 1', 'Manual Examination',
                 'Conduct detailed manual review of all files flagged as Suspicious '
                 'or Highly Suspicious, with particular focus on entropy outliers '
                 'and signature mismatches.'),
                ('Priority 2', 'Chain of Custody',
                 'Verify and document the provenance and custody history of all '
                 'flagged files before any further analysis to preserve evidential integrity.'),
                ('Priority 3', 'Advanced Analysis',
                 'Apply specialist steganography detection tools and decryption '
                 'attempts to high-entropy files that may contain concealed data.'),
                ('Priority 4', 'Legal Documentation',
                 'Compile all findings into a court-admissible evidence log, '
                 'including hash values, analysis timestamps, and tool version details.'),
            ]
        else:
            recs = [
                ('Action 1', 'Archive Report',
                 'Retain this report as a baseline integrity record for the '
                 'analysed file set.'),
                ('Action 2', 'Periodic Monitoring',
                 'Schedule periodic re-analysis to detect any future modifications '
                 'or additions to the monitored directories.'),
                ('Action 3', 'Reference Hashes',
                 'Store the generated hash values as a verified clean-state '
                 'reference for future comparison.'),
            ]

        rec_rows = [['Priority', 'Action', 'Detail']]
        for p, a, d in recs:
            rec_rows.append([
                Paragraph(p, ParagraphStyle('RP', parent=self.styles['TableCell'],
                                            fontName='Helvetica-Bold',
                                            textColor=C['navy'])),
                Paragraph(f'<b>{a}</b>', self.styles['TableCell']),
                Paragraph(d, self.styles['TableCell']),
            ])

        rt = Table(rec_rows, colWidths=[0.85*inch, 1.4*inch, 4.25*inch])
        rt.setStyle(self._base_table_style(header_bg=C['navy_mid']))
        content.append(rt)
        content.append(_sp(0.3))

        end_data = [[Paragraph(
            'END OF REPORT',
            ParagraphStyle('End', parent=self.styles['Normal'],
                           fontSize=9, fontName='Helvetica-Bold',
                           textColor=C['text_muted'], alignment=TA_CENTER))]]
        end_t = Table(end_data, colWidths=[6.5*inch])
        end_t.setStyle(TableStyle([
            ('BACKGROUND',    (0, 0), (-1, -1), C['slate_light']),
            ('GRID',          (0, 0), (-1, -1), 0.3, C['border']),
            ('TOPPADDING',    (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))
        content.append(end_t)

        return content