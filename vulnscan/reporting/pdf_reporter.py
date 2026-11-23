"""
Professional PDF Vulnerability Assessment Report Generator.
Implements a pure-Python, zero-dependency PDF 1.4 generator that formats
executive summaries, system identity, prioritized findings, remediation actions,
and evidence appendices into a paginated, multi-page professional security assessment document.
"""

import os
from typing import List, Tuple, Optional
from vulnscan.core.models import ScanReport, AssessmentStatus, Severity, AssessmentFinding


def sanitize_pdf_text(text: str) -> str:
    """Replaces Unicode quotes, dashes, symbols with safe ASCII equivalents for standard PDF fonts."""
    if not text:
        return ""
    replacements = {
        "\u2014": " -- ",  # em dash
        "\u2013": "-",     # en dash
        "\u2018": "'",     # left single quote
        "\u2019": "'",     # right single quote
        "\u201c": '"',     # left double quote
        "\u201d": '"',     # right double quote
        "\u2192": " -> ",  # right arrow
        "\u2190": " <- ",  # left arrow
        "\u2193": " v ",   # down arrow
        "\u2191": " ^ ",   # up arrow
        "\u2022": "* ",    # bullet
        "\u25cf": "* ",    # black circle
        "\u2714": "[x]",   # checkmark
        "\u2713": "[x]",   # checkmark
        "\u2717": "[ ]",   # cross mark
        "\u2718": "[ ]",   # cross mark
        "\u00a0": " ",     # non-breaking space
        "\t": "    ",      # tab
    }
    for k, v in replacements.items():
        text = text.replace(k, v)
    return text.encode("ascii", "replace").decode("ascii")


def wrap_text(text: str, max_chars: int) -> List[str]:
    """Wraps text cleanly at word boundaries and respects explicit newlines."""
    lines: List[str] = []
    for raw_line in text.split("\n"):
        raw_line = raw_line.strip()
        if not raw_line:
            lines.append("")
            continue
        words = raw_line.split(" ")
        curr_line: List[str] = []
        curr_len = 0
        for w in words:
            if not w:
                continue
            if len(w) > max_chars:
                if curr_line:
                    lines.append(" ".join(curr_line))
                    curr_line = []
                    curr_len = 0
                while len(w) > max_chars:
                    lines.append(w[:max_chars])
                    w = w[max_chars:]
                if w:
                    curr_line.append(w)
                    curr_len = len(w)
                continue

            added_len = len(w) + (1 if curr_line else 0)
            if curr_len + added_len <= max_chars:
                curr_line.append(w)
                curr_len += added_len
            else:
                lines.append(" ".join(curr_line))
                curr_line = [w]
                curr_len = len(w)
        if curr_line:
            lines.append(" ".join(curr_line))
    return lines


class PurePdfCanvas:
    """Zero-dependency minimal PDF 1.4 document builder with multi-line layout support."""

    def __init__(self, page_width: int = 612, page_height: int = 792, classification: str = "CONFIDENTIAL"):  # Letter size
        self.width = page_width
        self.height = page_height
        self.pages: List[str] = []
        self.current_stream: List[str] = []
        self.current_page_num = 0
        self.classification = classification

    def new_page(self):
        if self.current_stream:
            self.pages.append("\n".join(self.current_stream))
            self.current_stream = []
        self.current_page_num += 1

    def draw_rect(self, x: float, y: float, w: float, h: float, r: float, g: float, b: float, fill: bool = True):
        cmd = f"{r:.2f} {g:.2f} {b:.2f} {'rg' if fill else 'RG'} {x:.1f} {y:.1f} {w:.1f} {h:.1f} re {'f' if fill else 'S'}"
        self.current_stream.append(cmd)

    def draw_line(self, x1: float, y1: float, x2: float, y2: float, r: float = 0.5, g: float = 0.5, b: float = 0.5, width: float = 1.0):
        cmd = f"{r:.2f} {g:.2f} {b:.2f} RG {width:.1f} w {x1:.1f} {y1:.1f} m {x2:.1f} {y2:.1f} l S"
        self.current_stream.append(cmd)

    def draw_box(self, x: float, y: float, w: float, h: float,
                 bg_rgb: Tuple[float, float, float] = (0.96, 0.97, 0.98),
                 border_rgb: Tuple[float, float, float] = (0.80, 0.84, 0.88),
                 border_width: float = 0.8):
        """Draws a filled rectangle with a bordered outline."""
        # Fill
        r_f, g_f, b_f = bg_rgb
        self.draw_rect(x, y, w, h, r_f, g_f, b_f, fill=True)
        # Stroke Border
        r_b, g_b, b_b = border_rgb
        cmd = f"{r_b:.2f} {g_b:.2f} {b_b:.2f} RG {border_width:.1f} w {x:.1f} {y:.1f} {w:.1f} {h:.1f} re S"
        self.current_stream.append(cmd)

    def draw_text(self, text: str, x: float, y: float, size: int = 10, font: str = "F1", r: float = 0, g: float = 0, b: float = 0):
        safe = sanitize_pdf_text(text)
        clean_text = safe.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        cmd = f"BT /{font} {size} Tf {r:.2f} {g:.2f} {b:.2f} rg {x:.1f} {y:.1f} Td ({clean_text}) Tj ET"
        self.current_stream.append(cmd)

    def chars_for_width(self, width_pt: float, size: float, font: str = "F1") -> int:
        if font == "F3":
            char_w = 0.60 * size
        elif font == "F2":
            char_w = 0.55 * size
        else:
            char_w = 0.51 * size
        return max(15, int(width_pt / char_w))

    def draw_multiline_text(
        self,
        text: str,
        x: float,
        y: float,
        max_width: float,
        size: int = 8,
        font: str = "F1",
        line_height: float = 11,
        r: float = 0.1,
        g: float = 0.1,
        b: float = 0.1,
    ) -> float:
        """Draws multi-line text wrapped to max_width and returns the resulting y position."""
        max_chars = self.chars_for_width(max_width, size, font)
        lines = wrap_text(text, max_chars)
        curr_y = y
        for line in lines:
            if line:
                self.draw_text(line, x, curr_y, size=size, font=font, r=r, g=g, b=b)
            curr_y -= line_height
        return curr_y

    def measure_text_height(self, text: str, max_width: float, size: int = 8, font: str = "F1", line_height: float = 11) -> float:
        max_chars = self.chars_for_width(max_width, size, font)
        lines = wrap_text(text, max_chars)
        return max(1, len(lines)) * line_height

    def build_pdf(self) -> bytes:
        if self.current_stream:
            self.pages.append("\n".join(self.current_stream))
            self.current_stream = []

        total_pages = len(self.pages)
        offsets = [0]
        pdf_bytes = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

        def add_obj(body: str) -> int:
            offsets.append(len(pdf_bytes))
            obj_num = len(offsets) - 1
            raw = f"{obj_num} 0 obj\n{body}\nendobj\n".encode("latin1")
            pdf_bytes.extend(raw)
            return obj_num

        page_obj_ids = []
        content_obj_ids = []
        next_obj_id = 6

        for _ in range(total_pages):
            page_obj_ids.append(next_obj_id)
            content_obj_ids.append(next_obj_id + 1)
            next_obj_id += 2

        # Obj 1: Catalog
        add_obj("<< /Type /Catalog /Pages 2 0 R >>")

        # Obj 2: Pages
        kids_str = " ".join([f"{pid} 0 R" for pid in page_obj_ids])
        add_obj(f"<< /Type /Pages /Kids [{kids_str}] /Count {total_pages} >>")

        # Obj 3..5: Standard Fonts
        add_obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
        add_obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
        add_obj("<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>")

        # Pages and Streams
        for i, page_stream in enumerate(self.pages):
            pid = page_obj_ids[i]
            cid = content_obj_ids[i]

            footer_text = f"{self.classification}  |  Page {i+1} of {total_pages}  |  Linux Vulnerability Assessment Report"
            footer_stream = (
                f"\n0.84 0.87 0.91 RG 0.5 w 36 28 m 576 28 l S\n"
                f"BT /F1 7.5 Tf 0.45 0.50 0.55 rg 36 17 Td "
                f"({footer_text}) Tj ET\n"
            )
            full_stream = page_stream + footer_stream
            stream_len = len(full_stream.encode("latin1"))

            add_obj(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.width} {self.height}] /Contents {cid} 0 R /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> >>")
            add_obj(f"<< /Length {stream_len} >>\nstream\n{full_stream}\nendstream")

        xref_offset = len(pdf_bytes)
        num_objects = len(offsets)
        pdf_bytes.extend(f"xref\n0 {num_objects}\n0000000000 65535 f \n".encode("latin1"))
        for off in offsets[1:]:
            pdf_bytes.extend(f"{off:010d} 00000 n \n".encode("latin1"))

        trailer = f"trailer\n<< /Size {num_objects} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n"
        pdf_bytes.extend(trailer.encode("latin1"))
        return bytes(pdf_bytes)


class PdfReporter:
    @classmethod
    def _status_colors(cls, status: AssessmentStatus) -> Tuple[Tuple[float, float, float], Tuple[float, float, float], str]:
        """Returns (fill_rgb, border_rgb, label)."""
        if status == AssessmentStatus.AFFECTED:
            return (0.95, 0.88, 0.88), (0.85, 0.20, 0.20), "AFFECTED"
        if status == AssessmentStatus.POTENTIALLY_AFFECTED:
            return (0.98, 0.94, 0.86), (0.88, 0.55, 0.10), "POTENTIALLY AFFECTED"
        if status == AssessmentStatus.MITIGATED:
            return (0.94, 0.90, 0.98), (0.55, 0.30, 0.75), "MITIGATED"
        if status == AssessmentStatus.FIXED:
            return (0.88, 0.96, 0.92), (0.10, 0.65, 0.35), "FIXED"
        return (0.92, 0.94, 0.96), (0.45, 0.50, 0.55), "NOT AFFECTED"

    @classmethod
    def generate(cls, report: ScanReport, output_file: str) -> str:
        branding = getattr(report, "branding", None)
        classification = (branding.classification if branding and branding.classification else "CONFIDENTIAL").strip()
        company = branding.company_name if branding and branding.company_name else None
        assessor = branding.assessor_name if branding and branding.assessor_name else None

        pdf_canvas = PurePdfCanvas(classification=classification)
        sys = report.system_info
        summary = report.summary
        findings = report.findings

        # =========================================================================
        # PAGE 1: EXECUTIVE SUMMARY, TARGET IDENTITY & RISK OVERVIEW
        # =========================================================================
        pdf_canvas.new_page()

        # Header Title Banner
        pdf_canvas.draw_rect(36, 715, 540, 52, 0.07, 0.15, 0.28, fill=True)
        pdf_canvas.draw_text("LINUX VULNERABILITY ASSESSMENT REPORT", 48, 744, size=14, font="F2", r=1, g=1, b=1)

        # Classification badge (dynamically sized and right-aligned inside banner)
        clean_class = classification[:30]
        badge_w = min(150, max(85, len(clean_class) * 5.0 + 16))
        badge_x = 566 - badge_w
        pdf_canvas.draw_box(badge_x, 742, badge_w, 16, bg_rgb=(0.12, 0.22, 0.38), border_rgb=(0.38, 0.58, 0.88), border_width=0.8)
        pdf_canvas.draw_text(clean_class, badge_x + 8, 746, size=6.5, font="F2", r=0.90, g=0.95, b=1.0)
        pdf_canvas.draw_text(
            f"Target: {sys.hostname}  |  OS: {sys.os_name} {sys.os_version} ({sys.architecture})  |  Kernel: {sys.kernel_version}",
            48, 727, size=8.5, font="F1", r=0.82, g=0.88, b=0.96
        )

        # Assessment Metadata Block
        pdf_canvas.draw_box(36, 646, 540, 58, bg_rgb=(0.96, 0.97, 0.99), border_rgb=(0.82, 0.86, 0.92))
        brand_meta = f"  |  Org: {company}" if company else ""
        if assessor:
            brand_meta += f"  |  Assessor: {assessor}"
        pdf_canvas.draw_text(f"ASSESSMENT RUNTIME METADATA{brand_meta}", 46, 688, size=8, font="F2", r=0.15, g=0.25, b=0.40)
        pdf_canvas.draw_text(f"Scan Timestamp: {report.scan_timestamp}", 46, 673, size=8, font="F1", r=0.2, g=0.2, b=0.2)
        pdf_canvas.draw_text(f"Scanner Version: v{report.scanner_version} ({'Offline Mode' if report.is_offline_mode else 'Online Mode'})", 46, 658, size=8, font="F1", r=0.2, g=0.2, b=0.2)
        pdf_canvas.draw_text(f"Scan Duration: {summary.duration_seconds}s", 320, 673, size=8, font="F1", r=0.2, g=0.2, b=0.2)
        pdf_canvas.draw_text(f"Total Packages: {len(report.packages)}  |  Running Services: {len([s for s in report.services if s.is_running])}", 320, 658, size=8, font="F1", r=0.2, g=0.2, b=0.2)

        # Executive Metrics Cards
        y_metrics = 574
        pdf_canvas.draw_text("EXECUTIVE VULNERABILITY SUMMARY", 36, 626, size=10, font="F2", r=0.10, g=0.20, b=0.40)
        pdf_canvas.draw_line(36, 620, 576, 620, 0.82, 0.86, 0.90)

        card_w = 98
        gap = 12
        cards_data = [
            ("AFFECTED", summary.affected_count, (0.95, 0.88, 0.88), (0.85, 0.20, 0.20), (0.75, 0.10, 0.10)),
            ("POTENTIAL", summary.potentially_affected_count, (0.98, 0.94, 0.86), (0.88, 0.55, 0.10), (0.78, 0.40, 0.05)),
            ("MITIGATED", summary.mitigated_count, (0.94, 0.90, 0.98), (0.55, 0.30, 0.75), (0.45, 0.20, 0.65)),
            ("FIXED", summary.fixed_count, (0.88, 0.96, 0.92), (0.10, 0.65, 0.35), (0.05, 0.50, 0.25)),
            ("CISA KEV", summary.cisa_kev_count, (0.97, 0.86, 0.86), (0.80, 0.15, 0.15), (0.70, 0.05, 0.05)),
        ]

        for i, (label, count, bg, border, text_color) in enumerate(cards_data):
            cx = 36 + i * (card_w + gap)
            pdf_canvas.draw_box(cx, y_metrics, card_w, 42, bg_rgb=bg, border_rgb=border, border_width=1.0)
            pdf_canvas.draw_text(str(count), cx + (card_w / 2) - 6, y_metrics + 20, size=16, font="F2", r=text_color[0], g=text_color[1], b=text_color[2])
            pdf_canvas.draw_text(label, cx + 12, y_metrics + 6, size=7.5, font="F2", r=text_color[0], g=text_color[1], b=text_color[2])

        # Target System Profile Table
        y_sys = 552
        pdf_canvas.draw_text("TARGET SYSTEM PROFILE", 36, y_sys, size=10, font="F2", r=0.10, g=0.20, b=0.40)
        pdf_canvas.draw_line(36, y_sys - 4, 576, y_sys - 4, 0.82, 0.86, 0.90)

        sys_items = [
            ("Operating System", f"{sys.os_name} {sys.os_version} ({sys.os_codename or 'N/A'})"),
            ("Kernel Release", sys.kernel_version),
            ("Platform ID / Family", f"{sys.platform_id or 'N/A'} ({sys.os_family})"),
            ("Hardware Architecture", sys.architecture),
            ("CPU Processor", sys.cpu.model_name if sys.cpu else "Unknown"),
            ("Hardware Extensions", f"AVX-512: {'Yes' if (sys.cpu and sys.cpu.has_avx512) else 'No'} | VBMI: {'Active' if (sys.cpu and sys.cpu.has_avx512_vbmi) else 'Not Supported'}"),
            ("Virtualization / Cloud", f"{sys.virtualization or 'Bare-Metal'} / {sys.cloud_provider or 'On-Premise'}"),
        ]

        curr_y = y_sys - 18
        for label, val in sys_items:
            pdf_canvas.draw_text(label, 44, curr_y, size=8, font="F2", r=0.25, g=0.30, b=0.35)
            # Use wrapped or clean text
            pdf_canvas.draw_text(sanitize_pdf_text(val)[:65], 200, curr_y, size=8, font="F1", r=0.10, g=0.15, b=0.20)
            pdf_canvas.draw_line(44, curr_y - 3, 568, curr_y - 3, 0.92, 0.93, 0.95, width=0.5)
            curr_y -= 14

        # Prioritized Vulnerability Findings Overview Table on Page 1
        pdf_canvas.draw_text("TOP PRIORITIZED VULNERABILITY FINDINGS", 36, curr_y - 10, size=10, font="F2", r=0.10, g=0.20, b=0.40)
        pdf_canvas.draw_line(36, curr_y - 14, 576, curr_y - 14, 0.82, 0.86, 0.90)

        tbl_top = curr_y - 28
        pdf_canvas.draw_rect(36, tbl_top, 540, 15, 0.88, 0.91, 0.95, fill=True)
        pdf_canvas.draw_text("Rank", 40, tbl_top + 4, size=7.2, font="F2", r=0.15, g=0.20, b=0.30)
        pdf_canvas.draw_text("CVE ID", 64, tbl_top + 4, size=7.2, font="F2", r=0.15, g=0.20, b=0.30)
        pdf_canvas.draw_text("Component", 138, tbl_top + 4, size=7.2, font="F2", r=0.15, g=0.20, b=0.30)
        pdf_canvas.draw_text("Severity (CVSS)", 208, tbl_top + 4, size=7.2, font="F2", r=0.15, g=0.20, b=0.30)
        pdf_canvas.draw_text("Status", 272, tbl_top + 4, size=7.2, font="F2", r=0.15, g=0.20, b=0.30)
        pdf_canvas.draw_text("Context Risk", 344, tbl_top + 4, size=7.2, font="F2", r=0.15, g=0.20, b=0.30)
        pdf_canvas.draw_text("Action / Remediation", 440, tbl_top + 4, size=7.2, font="F2", r=0.15, g=0.20, b=0.30)

        row_y = tbl_top - 14
        if not findings:
            pdf_canvas.draw_text("No vulnerabilities matched the evaluated criteria or scoped CVE filter.", 44, row_y + 3, size=7.2, font="F1", r=0.45, g=0.45, b=0.45)
            pdf_canvas.draw_line(36, row_y, 576, row_y, 0.90, 0.92, 0.94, width=0.5)

        for f in findings[:8]:
            pdf_canvas.draw_text(f"#{f.priority_rank}", 40, row_y + 3, size=7.2, font="F1", r=0.2, g=0.2, b=0.2)
            pdf_canvas.draw_text(f.cve_id, 64, row_y + 3, size=7.2, font="F2", r=0.1, g=0.2, b=0.4)

            # Clean multi-package components (e.g. "java-17-openjdk, java-17-openjdk-headless")
            comp_name = f.component.split(",")[0].strip()
            pdf_canvas.draw_text(comp_name[:15], 138, row_y + 3, size=7.2, font="F1", r=0.2, g=0.2, b=0.2)

            sev_color = (0.75, 0.1, 0.1) if f.severity in (Severity.CRITICAL, Severity.HIGH) else (0.2, 0.2, 0.2)
            cvss_str = f"{f.severity.value} ({f.cvss_score})" if f.cvss_score else f.severity.value
            pdf_canvas.draw_text(cvss_str, 208, row_y + 3, size=7.2, font="F1", r=sev_color[0], g=sev_color[1], b=sev_color[2])

            _, _, st_label = cls._status_colors(f.status)
            status_display = "POTENTIAL" if st_label == "POTENTIALLY AFFECTED" else st_label
            pdf_canvas.draw_text(status_display[:13], 272, row_y + 3, size=7.2, font="F2", r=0.1, g=0.3, b=0.5)

            # Contextual risk without ugly truncation
            ctx_risk = f.contextual_risk_rating
            if "Component Absent" in ctx_risk:
                ctx_risk = "None (Absent)"
            elif "Prerequisites Not Met" in ctx_risk:
                ctx_risk = "None (Prereq)"
            elif "Inactive Daemon" in ctx_risk:
                ctx_risk = "Low (Inactive)"
            pdf_canvas.draw_text(ctx_risk[:16], 344, row_y + 3, size=7.2, font="F1", r=0.25, g=0.25, b=0.25)

            # Complete, professional Action / Remediation text without truncated trailing words
            if f.status == AssessmentStatus.FIXED:
                act_text = "Package is up-to-date"
            elif f.status == AssessmentStatus.NOT_AFFECTED:
                act_text = "No action required"
            elif f.status == AssessmentStatus.MITIGATED:
                act_text = "Mitigated by configuration"
            elif f.remediation_cmd:
                act_text = f.remediation_cmd.strip()[:34]
            elif f.remediation:
                first_sent = f.remediation.split(".")[0].strip()
                if len(first_sent) > 28:
                    words = first_sent.split(" ")
                    short = ""
                    for w in words:
                        if len(short) + len(w) + 1 <= 26:
                            short = (short + " " + w).strip()
                        else:
                            break
                    act_text = short if short else first_sent[:26]
                else:
                    act_text = first_sent
            else:
                act_text = "Review Advisory"

            pdf_canvas.draw_text(act_text, 440, row_y + 3, size=7.0, font="F1", r=0.1, g=0.2, b=0.4)

            pdf_canvas.draw_line(36, row_y, 576, row_y, 0.90, 0.92, 0.94, width=0.5)
            row_y -= 14

        # =========================================================================
        # PAGE 2+: DETAILED EVIDENCE-BASED AUDIT & FINDINGS (SECTIONS A - G)
        # =========================================================================
        def draw_section_heading(title: str):
            nonlocal curr_y
            # 15 pt height bar across full width with colored accent on left
            pdf_canvas.draw_box(36, curr_y - 15, 540, 15, bg_rgb=(0.91, 0.94, 0.98), border_rgb=(0.76, 0.83, 0.92), border_width=0.8)
            pdf_canvas.draw_rect(36, curr_y - 15, 4, 15, 0.18, 0.40, 0.75, fill=True)
            pdf_canvas.draw_text(title, 46, curr_y - 11, size=7.5, font="F2", r=0.10, g=0.22, b=0.45)
            curr_y -= 26  # Clean 11 pt gap under heading bar before section text starts

        for f in findings:
            # Each finding gets its own dedicated, unfragmented page
            pdf_canvas.new_page()
            curr_y = 750

            # Finding Header Banner Card
            fill_rgb, border_rgb, st_label = cls._status_colors(f.status)
            header_h = 30
            pdf_canvas.draw_box(36, curr_y - header_h, 540, header_h, bg_rgb=(0.95, 0.97, 0.99), border_rgb=(0.75, 0.80, 0.88), border_width=1.0)
            # Left accent strip for Status
            pdf_canvas.draw_rect(36, curr_y - header_h, 5, header_h, border_rgb[0], border_rgb[1], border_rgb[2], fill=True)

            kev_chip = " [CISA KEV]" if f.cisa_kev else ""
            title_line = f"Finding #{f.priority_rank}: {f.cve_id} -- {f.title}{kev_chip}"
            title_lines = wrap_text(sanitize_pdf_text(title_line), 78)
            if len(title_lines) == 1:
                pdf_canvas.draw_text(title_lines[0], 48, curr_y - 19, size=9, font="F2", r=0.08, g=0.18, b=0.34)
            else:
                pdf_canvas.draw_text(title_lines[0], 48, curr_y - 13, size=8.5, font="F2", r=0.08, g=0.18, b=0.34)
                pdf_canvas.draw_text(title_lines[1][:78], 48, curr_y - 24, size=8.0, font="F2", r=0.08, g=0.18, b=0.34)

            # Status Badge Pill on Right
            pdf_canvas.draw_box(472, curr_y - 23, 96, 17, bg_rgb=fill_rgb, border_rgb=border_rgb, border_width=1.0)
            pdf_canvas.draw_text(st_label, 480, curr_y - 17, size=7, font="F2", r=border_rgb[0], g=border_rgb[1], b=border_rgb[2])
            curr_y -= (header_h + 8)

            # Metadata Bar: Component, Versions, CVSS, EPSS
            epss_str = f"{round(f.epss_score * 100, 1)}%" if f.epss_score is not None else "N/A"
            meta_line = (
                f"Component: {f.component}  |  Installed: {f.installed_version}  |  "
                f"Fixed: {f.fixed_version or 'N/A'}  |  CVSS: {f.cvss_score or 'N/A'} ({f.severity.value})  |  EPSS: {epss_str}"
            )
            pdf_canvas.draw_box(36, curr_y - 16, 540, 16, bg_rgb=(0.96, 0.97, 0.99), border_rgb=(0.84, 0.88, 0.92), border_width=0.6)
            pdf_canvas.draw_text(meta_line, 44, curr_y - 12, size=7.5, font="F1", r=0.20, g=0.25, b=0.35)
            curr_y -= 26

            # --- Section A: Overview & Root Cause ---
            draw_section_heading("SECTION A: VULNERABILITY OVERVIEW & ROOT CAUSE")
            desc_text = f"Overview: {f.description or f.title}"
            curr_y = pdf_canvas.draw_multiline_text(desc_text, 44, curr_y, max_width=524, size=7.5, font="F1", line_height=11.5, r=0.15, g=0.15, b=0.15)
            curr_y -= 5
            rc_text = f"Root Cause: {f.root_cause or 'Vulnerability in target software logic or memory handling.'}"
            curr_y = pdf_canvas.draw_multiline_text(rc_text, 44, curr_y, max_width=524, size=7.5, font="F1", line_height=11.5, r=0.25, g=0.25, b=0.25)
            curr_y -= 11

            # --- Section B: Environment & Applicability Analysis ---
            draw_section_heading("SECTION B: ENVIRONMENT & APPLICABILITY ANALYSIS")
            env_line = f"Host: {sys.os_name} {sys.os_version} ({sys.platform_id or sys.os_family})  |  Kernel: {sys.kernel_version}  |  Arch: {sys.architecture}"
            pdf_canvas.draw_text(env_line, 44, curr_y, size=7.5, font="F1", r=0.2, g=0.2, b=0.2)
            curr_y -= 12
            app_text = f"Applicability: [{st_label}] {f.applicability_reason}"
            curr_y = pdf_canvas.draw_multiline_text(app_text, 44, curr_y, max_width=524, size=7.5, font="F1", line_height=11.5, r=0.1, g=0.2, b=0.35)
            curr_y -= 4
            p_met = ", ".join(f.prerequisites_met) if f.prerequisites_met else "None"
            p_not_met = ", ".join(f.prerequisites_not_met) if f.prerequisites_not_met else "None"
            curr_y = pdf_canvas.draw_multiline_text(f"Prerequisites Met: {p_met}", 44, curr_y, max_width=524, size=7.2, font="F1", line_height=11.0, r=0.3, g=0.3, b=0.3)
            curr_y -= 2
            curr_y = pdf_canvas.draw_multiline_text(f"Prerequisites Shielded/Unmet: {p_not_met}", 44, curr_y, max_width=524, size=7.2, font="F1", line_height=11.0, r=0.3, g=0.3, b=0.3)
            curr_y -= 11

            # --- Section C: Step-by-Step Findings & Audited Evidence ---
            draw_section_heading("SECTION C: STEP-BY-STEP FINDINGS & AUDITED EVIDENCE")
            if f.validation_steps:
                for s in f.validation_steps[:3]:
                    cmd = s.get('command', '')
                    purpose = s.get('purpose', '')
                    exp = s.get('expected_output', '').strip() or s.get('expected', '').strip()
                    exp_str = f" [Expected: {exp}]" if exp else ""
                    step_text = f"* Check: {cmd} -> {purpose}{exp_str}"
                    curr_y = pdf_canvas.draw_multiline_text(step_text, 44, curr_y, max_width=524, size=7.2, font="F1", line_height=11.0, r=0.2, g=0.25, b=0.3)
                    curr_y -= 2
                curr_y -= 3

            if f.evidence:
                ev = f.evidence[0]
                ev_cmd = f"$ {ev.command}"
                ev_out = f"Output: {ev.output_snippet}"
                h_cmd = pdf_canvas.measure_text_height(ev_cmd, max_width=512, size=7, font="F3", line_height=10.5)
                h_out = pdf_canvas.measure_text_height(ev_out, max_width=512, size=7, font="F3", line_height=10.5)
                box_h = h_cmd + h_out + 12
                pdf_canvas.draw_box(44, curr_y - box_h, 524, box_h, bg_rgb=(0.97, 0.98, 0.99), border_rgb=(0.80, 0.85, 0.90), border_width=0.6)
                box_y = curr_y - 8
                box_y = pdf_canvas.draw_multiline_text(ev_cmd, 52, box_y, max_width=512, size=7, font="F3", line_height=10.5, r=0.08, g=0.25, b=0.45)
                box_y = pdf_canvas.draw_multiline_text(ev_out, 52, box_y, max_width=512, size=7, font="F3", line_height=10.5, r=0.15, g=0.35, b=0.20)
                curr_y -= (box_h + 11)

            # --- Section D: Safe Reproduction & Verification (PoC) ---
            safe_text = f.safe_verification_procedure or "Inspect installed package EVR and vendor changelog entries via local package manager."
            draw_section_heading("SECTION D: SAFE REPRODUCTION & NON-DESTRUCTIVE VERIFICATION (PoC)")
            h_safe = pdf_canvas.measure_text_height(safe_text, max_width=512, size=7.2, font="F1", line_height=11.0)
            box_h = h_safe + 12
            pdf_canvas.draw_box(44, curr_y - box_h, 524, box_h, bg_rgb=(0.95, 0.98, 0.95), border_rgb=(0.60, 0.85, 0.65), border_width=0.7)
            box_y = curr_y - 8
            box_y = pdf_canvas.draw_multiline_text(safe_text, 52, box_y, max_width=512, size=7.2, font="F1", line_height=11.0, r=0.05, g=0.35, b=0.15)
            curr_y -= (box_h + 11)

            # --- Section E: Actionable Remediation Guidance ---
            draw_section_heading("SECTION E: ACTIONABLE REMEDIATION GUIDANCE")
            rem_text = f"Vendor Recommendation: {f.remediation}"
            curr_y = pdf_canvas.draw_multiline_text(rem_text, 44, curr_y, max_width=524, size=7.5, font="F1", line_height=11.5, r=0.15, g=0.15, b=0.15)
            if f.remediation_cmd:
                curr_y -= 3
                cmd_str = f"$ {f.remediation_cmd}"
                h_cmd = pdf_canvas.measure_text_height(cmd_str, max_width=512, size=7, font="F3", line_height=10.5)
                box_h = h_cmd + 10
                pdf_canvas.draw_box(44, curr_y - box_h, 524, box_h, bg_rgb=(0.99, 0.98, 0.92), border_rgb=(0.90, 0.82, 0.50), border_width=0.6)
                pdf_canvas.draw_multiline_text(cmd_str, 52, curr_y - 7, max_width=512, size=7, font="F3", line_height=10.5, r=0.55, g=0.30, b=0.0)
                curr_y -= (box_h + 7)
            else:
                curr_y -= 4
            reboot_str = f"Reboot Required: {'Yes' if f.requires_reboot else 'No'}  |  Service Restart: {'Yes' if f.requires_service_restart else 'No'}  |  Impact: {f.operational_impact or 'Standard package upgrade'}"
            pdf_canvas.draw_text(reboot_str, 44, curr_y, size=7.2, font="F1", r=0.3, g=0.3, b=0.3)
            curr_y -= 11

            # --- Section F: Contextual Risk Assessment & Compensating Controls ---
            draw_section_heading("SECTION F: CONTEXTUAL RISK ASSESSMENT & COMPENSATING CONTROLS")
            risk_eval = f"Inherent Severity: {f.severity.value} (CVSS: {f.cvss_score or 'N/A'})   -->   Contextual Operational Risk: {f.contextual_risk_rating}"
            pdf_canvas.draw_text(risk_eval, 44, curr_y, size=7.5, font="F2", r=0.10, g=0.20, b=0.35)
            curr_y -= 12
            pdf_canvas.draw_text("Active Compensating Controls & Boundary Protections:", 44, curr_y, size=7.2, font="F2", r=0.15, g=0.20, b=0.30)
            curr_y -= 10
            if f.compensating_controls:
                for c in f.compensating_controls:
                    curr_y = pdf_canvas.draw_multiline_text(f"  [x] {c}", 48, curr_y, max_width=516, size=7.2, font="F1", line_height=10.8, r=0.25, g=0.25, b=0.25)
                    curr_y -= 2
            else:
                curr_y = pdf_canvas.draw_multiline_text("  None documented for this specific CVE.", 48, curr_y, max_width=516, size=7.2, font="F1", line_height=10.8, r=0.4, g=0.4, b=0.4)
                curr_y -= 2
            curr_y -= 3
            curr_y = pdf_canvas.draw_multiline_text(f"Residual Risk: {f.residual_risk or 'Minimal under documented controls.'}", 44, curr_y, max_width=524, size=7.2, font="F1", line_height=10.8, r=0.25, g=0.25, b=0.25)
            curr_y -= 11

            # --- Section G: Conclusion & Remediation Priority ---
            draw_section_heading("SECTION G: CONCLUSION & AUDIT DETERMINATION")
            concl_line = (
                f"Determination: {st_label}  |  Remediation Priority: {f.remediation_priority}  |  "
                f"Priority Score: {f.risk_priority_score}/100  |  Confidence: {f.confidence.value}"
            )
            pdf_canvas.draw_text(concl_line, 44, curr_y, size=7.5, font="F2", r=0.10, g=0.25, b=0.40)
            curr_y -= 12
            if f.risk_justification:
                curr_y = pdf_canvas.draw_multiline_text(f"Risk Justification: {f.risk_justification}", 44, curr_y, max_width=524, size=7.2, font="F1", line_height=11.0, r=0.3, g=0.3, b=0.3)
            curr_y -= 8
            pdf_canvas.draw_line(36, curr_y, 576, curr_y, 0.78, 0.82, 0.88, width=0.8)

        # Build and write final PDF
        pdf_bytes = pdf_canvas.build_pdf()
        with open(output_file, "wb") as f_out:
            f_out.write(pdf_bytes)
        return output_file
