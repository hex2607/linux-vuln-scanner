"""
Interactive HTML Vulnerability Assessment Report Generator.
Generates a standalone, self-contained, responsive modern HTML security report
with embedded CSS, interactive search, severity filtering, status filtering,
evidence drawers, and print-ready stylesheet.
"""

import json
from vulnscan.core.models import ScanReport, AssessmentStatus, Severity


class HtmlReporter:
    @classmethod
    def generate(cls, report: ScanReport, output_file: str) -> str:
        html = cls.render_html(report)
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)
        return output_file

    @classmethod
    def render_html(cls, report: ScanReport) -> str:
        sys = report.system_info
        summary = report.summary
        findings = report.findings

        # Severity colors
        # Critical: #dc2626 (Red), High: #ea580c (Orange), Medium: #d97706 (Amber), Low: #2563eb (Blue)
        # Status colors:
        # Affected: #ef4444, Potentially Affected: #f59e0b, Mitigated: #8b5cf6, Fixed: #10b981, Not Affected: #6b7280

        findings_rows = []
        for f in findings:
            sev_class = f.severity.value.lower()
            status_slug = f.status.value.lower().replace(" ", "-")

            cisa_badge = '<span class="badge badge-cisa">CISA KEV</span>' if f.cisa_kev else ''
            epss_val = f"{round(f.epss_score * 100, 1)}%" if f.epss_score is not None else 'N/A'

            evidence_items_html = ""
            for ev in f.evidence:
                evidence_items_html += f"""
                <div class="evidence-box">
                    <div class="evidence-cmd"><code>$ {ev.command}</code></div>
                    <div class="evidence-meta">Source: {ev.source_file_or_target} | Interpretation: {ev.interpretation}</div>
                    <pre class="evidence-output">{ev.output_snippet}</pre>
                </div>
                """

            remed_box = ""
            if f.remediation_cmd:
                remed_box += f"""
                <div class="remed-section">
                    <strong>Remediation Command:</strong>
                    <pre><code>{f.remediation_cmd}</code></pre>
                </div>
                """
            if f.verification_cmd:
                remed_box += f"""
                <div class="remed-section">
                    <strong>Verification Command:</strong>
                    <pre><code>{f.verification_cmd}</code></pre>
                </div>
                """
            if f.mitigation:
                remed_box += f"""
                <div class="remed-section">
                    <strong>Temporary Mitigation:</strong>
                    <div class="mitigation-text">{f.mitigation}</div>
                </div>
                """

            refs_html = "".join([f'<li><a href="{r}" target="_blank" rel="noopener">{r}</a></li>' for r in f.references])

            # Validation steps table
            steps_html = ""
            if f.validation_steps:
                steps_rows = ""
                for st in f.validation_steps:
                    steps_rows += f"""
                    <tr>
                        <td style="width: 25%;"><strong>{st.get('step', '')}</strong></td>
                        <td style="width: 30%;"><code>{st.get('command', '')}</code></td>
                        <td style="width: 20%;">{st.get('purpose', '')}</td>
                        <td style="width: 25%;"><code class="code-exp">{st.get('expected_output', '')}</code></td>
                    </tr>
                    """
                steps_html = f"""
                <table class="sub-table">
                    <thead>
                        <tr><th>Check / Step</th><th>Command</th><th>Purpose</th><th>Expected Output</th></tr>
                    </thead>
                    <tbody>{steps_rows}</tbody>
                </table>
                """

            comp_controls_html = "".join([f"<li>{c}</li>" for c in f.compensating_controls]) or "<li>No specific compensating controls documented.</li>"

            row = f"""
            <tr class="finding-row sev-{sev_class} status-{status_slug}" data-cve="{f.cve_id}" data-comp="{f.component}" data-sev="{f.severity.value}" data-status="{f.status.value}">
                <td class="col-rank">#{f.priority_rank}</td>
                <td class="col-cve">
                    <strong>{f.cve_id}</strong>
                    {cisa_badge}
                    <div class="sub-text">{f.title}</div>
                </td>
                <td class="col-comp">
                    <code>{f.component}</code>
                    <div class="sub-text">Inst: {f.installed_version}</div>
                    <div class="sub-text">Fix: {f.fixed_version or 'N/A'}</div>
                </td>
                <td class="col-sev">
                    <span class="badge badge-sev-{sev_class}">{f.severity.value}</span>
                    <div class="sub-text">CVSS: {f.cvss_score or 'N/A'}</div>
                    <div class="sub-text">EPSS: {epss_val}</div>
                </td>
                <td class="col-status">
                    <span class="badge badge-status-{status_slug}">{f.status.value}</span>
                    <div class="sub-text">Context: <strong>{f.contextual_risk_rating}</strong></div>
                </td>
                <td class="col-score">
                    <div class="risk-score-circle">{f.risk_priority_score}</div>
                </td>
                <td class="col-actions">
                    <button class="btn-toggle" onclick="toggleDetails('{f.cve_id}')">Audit Details &darr;</button>
                </td>
            </tr>
            <tr id="details-{f.cve_id}" class="details-row" style="display: none;">
                <td colspan="7">
                    <div class="details-pane">
                        <div class="audit-section-card">
                            <div class="section-badge">Section A: Vulnerability Overview & Root Cause</div>
                            <div class="audit-section-content">
                                <p><strong>Vulnerability:</strong> <strong>{f.cve_id}</strong> &mdash; {f.title}</p>
                                <p><strong>Affected Component:</strong> <code>{f.component}</code></p>
                                <p><strong>Technical Description:</strong> {f.description or f.title}</p>
                                <p><strong>Root Cause:</strong> {f.root_cause or 'Vulnerability in target component logic.'}</p>
                                <p><strong>Inherent CVSS:</strong> <span class="badge badge-sev-{sev_class}">{f.severity.value} ({f.cvss_score or 'N/A'})</span> | <strong>Vector:</strong> <code>{f.cvss_vector or 'N/A'}</code></p>
                                <p><strong>Threat Intelligence:</strong> CISA KEV: {'<span class="badge badge-cisa">YES &mdash; Actively Exploited</span>' if f.cisa_kev else '<span class="badge">No Known In-The-Wild Exploitation</span>'} | EPSS Exploit Probability: <strong>{epss_val}</strong></p>
                            </div>
                        </div>

                        <div class="audit-section-card">
                            <div class="section-badge">Section B: Environment & Applicability Analysis</div>
                            <div class="audit-section-content">
                                <p><strong>Operating System:</strong> {sys.os_name} {sys.os_version} ({sys.platform_id or sys.os_family}) | Kernel: <code>{sys.kernel_version}</code> ({sys.architecture})</p>
                                <p><strong>Installed Version:</strong> <code>{f.installed_version}</code> | <strong>Vendor Fixed Release:</strong> <code>{f.fixed_version or 'N/A'}</code></p>
                                <p><strong>Applicability Determination:</strong> <span class="badge badge-status-{status_slug}">{f.status.value}</span> &mdash; {f.applicability_reason}</p>
                                <p class="sub-text" style="margin-top:6px; font-style:italic;">Evaluated via vendor backport errata analysis instead of naive upstream version comparison.</p>
                                <div class="prereq-container">
                                    <div class="prereq-col">
                                        <strong>Prerequisites Met:</strong>
                                        <ul>{"".join([f'<li>{p}</li>' for p in f.prerequisites_met]) or '<li>None</li>'}</ul>
                                    </div>
                                    <div class="prereq-col">
                                        <strong>Prerequisites Not Met / Shielded:</strong>
                                        <ul>{"".join([f'<li>{p}</li>' for p in f.prerequisites_not_met]) or '<li>None</li>'}</ul>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="audit-section-card">
                            <div class="section-badge">Section C: Step-by-Step Findings & Validation</div>
                            <div class="audit-section-content">
                                <p>Sequential investigation executed against target host using non-destructive audit commands:</p>
                                {steps_html}
                                <h4 style="margin-top: 14px; margin-bottom: 8px;">Audited Evidence Collected from Target Server</h4>
                                {evidence_items_html}
                            </div>
                        </div>

                        <div class="audit-section-card">
                            <div class="section-badge">Section D: Reproduction & Proof of Concept (PoC) / Non-Destructive Validation</div>
                            <div class="audit-section-content">
                                <p><strong>Controlled Test Environment Procedure & Non-Destructive Check:</strong></p>
                                <div class="safe-verify-box">{f.safe_verification_procedure or 'Inspect binary version and changelog via standard package manager commands.'}</div>
                                <p class="sub-text" style="margin-top:6px; font-style:italic;">Safety Note: Destructive actions or weaponized exploits are avoided. Non-destructive behavioral checks or vendor changelog validations are used to confirm applicability safely.</p>
                            </div>
                        </div>

                        <div class="audit-section-card">
                            <div class="section-badge">Section E: Remediation Guidance</div>
                            <div class="audit-section-content">
                                <p><strong>Vendor-Recommended Action:</strong> {f.remediation}</p>
                                {remed_box}
                                <p style="margin-top: 10px;"><strong>Reboot Required:</strong> {'Yes' if f.requires_reboot else 'No'} | <strong>Service Restart Required:</strong> {'Yes (' + (f.affected_service_name or 'service') + ')' if f.requires_service_restart else 'No'}</p>
                                <p><strong>Operational Impact:</strong> {f.operational_impact or 'Standard package upgrade.'}</p>
                            </div>
                        </div>

                        <div class="audit-section-card">
                            <div class="section-badge">Section F: Risk Assessment & Compensating Controls</div>
                            <div class="audit-section-content">
                                <div class="risk-compare-box">
                                    <div><strong>Inherent Severity:</strong> <span class="badge badge-sev-{sev_class}">{f.severity.value} ({f.cvss_score or 'N/A'})</span></div>
                                    <div><strong>Contextual Risk on Host:</strong> <span class="badge" style="background:#0284c7; color:#fff;">{f.contextual_risk_rating}</span></div>
                                </div>
                                <p style="margin-top: 10px;"><strong>Active Compensating Controls:</strong></p>
                                <ul>{comp_controls_html}</ul>
                                <p style="margin-top: 10px;"><strong>Residual Risk (if deferred):</strong> {f.residual_risk or 'Minimal under current operating conditions.'}</p>
                            </div>
                        </div>

                        <div class="audit-section-card">
                            <div class="section-badge">Section G: Final Conclusion & Priority Justification</div>
                            <div class="audit-section-content">
                                <p><strong>Final Classification:</strong> <span class="badge badge-status-{status_slug}">{f.status.value}</span> (Confidence: <strong>{f.confidence.value}</strong>)</p>
                                <p><strong>Remediation Priority:</strong> <strong>{f.remediation_priority}</strong> (Risk Priority Score: <strong>{f.risk_priority_score}</strong> / 100)</p>
                                <p><strong>Risk Treatment Justification:</strong> {f.risk_justification}</p>

                                <h4 style="margin-top: 14px; margin-bottom: 8px;">Advisory & Authoritative References</h4>
                                <p>Source: {f.advisory_source} ({f.advisory_id})</p>
                                <ul>{refs_html}</ul>
                            </div>
                        </div>
                    </div>
                </td>
            </tr>
            """
            findings_rows.append(row)

        if not findings_rows:
            findings_table_html = '<tr><td colspan="7" style="text-align:center; padding: 32px; color: #94a3b8; font-size: 0.95rem;">No vulnerabilities matched the evaluated criteria or scoped CVE filter.</td></tr>'
        else:
            findings_table_html = "\n".join(findings_rows)

        # Inventory packages rows (top 50)
        pkg_rows = []
        for p in report.packages[:50]:
            pkg_rows.append(f"<tr><td><code>{p.name}</code></td><td>{p.version}</td><td>{p.release}</td><td>{p.arch}</td><td>{p.vendor}</td></tr>")
        pkg_table_html = "\n".join(pkg_rows)

        # HTML Template
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {sys.hostname}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --surface: #1e293b;
            --surface-hover: #334155;
            --text: #f8fafc;
            --text-muted: #94a3b8;
            --border: #334155;
            --primary: #3b82f6;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #3b82f6;
            --affected: #ef4444;
            --potential: #f59e0b;
            --mitigated: #a855f7;
            --fixed: #10b981;
            --not-affected: #64748b;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            line-height: 1.5;
            padding: 24px;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        header {{
            background: var(--surface);
            padding: 24px;
            border-radius: 12px;
            border: 1px solid var(--border);
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
        }}
        h1 {{ font-size: 24px; font-weight: 700; color: #fff; }}
        h2 {{ font-size: 18px; margin-bottom: 16px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }}
        h4 {{ font-size: 14px; text-transform: uppercase; color: var(--text-muted); margin: 16px 0 8px 0; }}
        .header-meta {{ color: var(--text-muted); font-size: 14px; }}
        
        .grid-summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .card {{
            background: var(--surface);
            padding: 20px;
            border-radius: 10px;
            border: 1px solid var(--border);
        }}
        .card-num {{ font-size: 32px; font-weight: 800; }}
        .card-label {{ font-size: 13px; text-transform: uppercase; color: var(--text-muted); }}
        
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }}
        .badge-sev-critical {{ background: #7f1d1d; color: #fecaca; }}
        .badge-sev-high {{ background: #7c2d12; color: #fed7aa; }}
        .badge-sev-medium {{ background: #78350f; color: #fef08a; }}
        .badge-sev-low {{ background: #1e3a8a; color: #bfdbfe; }}
        
        .badge-status-affected {{ background: #7f1d1d; color: #fecaca; border: 1px solid #ef4444; }}
        .badge-status-potentially-affected {{ background: #78350f; color: #fef08a; border: 1px solid #f59e0b; }}
        .badge-status-mitigated {{ background: #581c87; color: #e9d5ff; border: 1px solid #a855f7; }}
        .badge-status-fixed {{ background: #064e3b; color: #a7f3d0; border: 1px solid #10b981; }}
        .badge-status-not-affected {{ background: #334155; color: #cbd5e1; }}
        .badge-cisa {{ background: #991b1b; color: #fff; font-size: 10px; margin-left: 6px; }}

        .risk-score-circle {{
            font-weight: 800;
            font-size: 15px;
            background: #0f172a;
            border: 2px solid var(--border);
            width: 44px;
            height: 44px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 50%;
        }}

        .filter-bar {{
            background: var(--surface);
            padding: 16px;
            border-radius: 10px;
            border: 1px solid var(--border);
            margin-bottom: 20px;
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            align-items: center;
        }}
        input[type="text"] {{
            flex: 1;
            min-width: 250px;
            padding: 8px 12px;
            background: #0f172a;
            border: 1px solid var(--border);
            color: #fff;
            border-radius: 6px;
        }}
        select, button {{
            padding: 8px 14px;
            background: #334155;
            color: #fff;
            border: 1px solid var(--border);
            border-radius: 6px;
            cursor: pointer;
        }}
        button:hover {{ background: #475569; }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 24px;
            font-size: 14px;
        }}
        th, td {{
            padding: 12px 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }}
        th {{
            background: #111827;
            color: var(--text-muted);
            text-transform: uppercase;
            font-size: 12px;
        }}
        tr.finding-row:hover {{ background: var(--surface-hover); }}
        .sub-text {{ font-size: 12px; color: var(--text-muted); margin-top: 3px; }}
        code {{ background: #0f172a; padding: 2px 5px; border-radius: 4px; font-family: monospace; }}
        
        .details-pane {{
            background: #090e17;
            padding: 24px 20px;
            border-radius: 8px;
            border: 1px solid #1e293b;
            margin: 12px 0 18px 0;
        }}
        .audit-section-card {{
            background: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 20px 22px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.25);
        }}
        .audit-section-card:last-child {{
            margin-bottom: 0;
        }}
        .prereq-container {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 18px;
            margin: 14px 0;
        }}
        .prereq-col {{ background: #1e293b; padding: 14px 18px; border-radius: 6px; font-size: 13px; line-height: 1.5; }}
        .prereq-col ul {{ margin-left: 20px; margin-top: 8px; }}
        
        .evidence-box {{
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 6px;
            padding: 14px 18px;
            margin: 14px 0;
        }}
        .evidence-cmd {{ font-family: monospace; color: #38bdf8; font-size: 13px; }}
        .evidence-meta {{ font-size: 12px; color: var(--text-muted); margin: 6px 0; }}
        .evidence-output {{
            background: #090d16;
            padding: 10px 14px;
            border-radius: 4px;
            font-size: 12.5px;
            color: #a7f3d0;
            overflow-x: auto;
            margin-top: 6px;
            line-height: 1.5;
        }}
        .remed-section {{ margin: 14px 0; }}
        .remed-section pre {{
            background: #090d16;
            padding: 12px 16px;
            border-radius: 6px;
            color: #fbbf24;
            font-family: monospace;
            margin-top: 6px;
            font-size: 13px;
        }}
        .mitigation-text {{ color: #cbd5e1; font-size: 13px; margin-top: 6px; }}
        
        .section-badge {{
            display: inline-flex;
            align-items: center;
            background: #1e3a8a;
            color: #93c5fd;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            padding: 5px 12px;
            border-radius: 4px;
            margin: 0 0 14px 0;
            border-left: 3px solid #3b82f6;
        }}
        .audit-section-content {{
            font-size: 13.5px;
            line-height: 1.65;
            color: #cbd5e1;
        }}
        .audit-section-content p {{
            margin-bottom: 10px;
            line-height: 1.65;
        }}
        .audit-section-content p:last-child {{
            margin-bottom: 0;
        }}
        .audit-section-content strong {{
            color: #f8fafc;
        }}
        .audit-section-content ul {{
            margin: 8px 0 12px 24px;
            line-height: 1.6;
        }}
        .audit-section-content li {{
            margin-bottom: 6px;
        }}
        .sub-table {{
            width: 100%;
            margin: 12px 0 18px 0;
            border: 1px solid #334155;
            background: #090d16;
            border-radius: 6px;
            font-size: 12.5px;
        }}
        .sub-table th {{
            background: #1e293b;
            color: #94a3b8;
            padding: 10px 12px;
        }}
        .sub-table td {{
            padding: 10px 12px;
            border-bottom: 1px solid #1e293b;
        }}
        .code-exp {{
            color: #34d399;
            background: #111827;
            padding: 3px 6px;
            border-radius: 3px;
        }}
        .safe-verify-box {{
            background: #062419;
            border: 1px solid #059669;
            border-left: 4px solid #10b981;
            padding: 14px 18px;
            border-radius: 6px;
            font-size: 13.5px;
            color: #d1fae5;
            margin: 14px 0;
            line-height: 1.6;
        }}
        .risk-compare-box {{
            display: flex;
            gap: 24px;
            background: #1e293b;
            padding: 12px 18px;
            border-radius: 6px;
            margin: 14px 0;
            font-size: 13.5px;
            align-items: center;
        }}

        .btn-action {{
            padding: 8px 16px;
            font-size: 13px;
            font-weight: 600;
            border-radius: 6px;
            border: 1px solid var(--border);
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            gap: 6px;
            transition: all 0.15s ease;
        }}
        .btn-print {{
            background: #0284c7;
            color: #ffffff;
            border-color: #0369a1;
        }}
        .btn-print:hover {{
            background: #0369a1;
        }}
        .btn-expand {{
            background: #334155;
            color: #f8fafc;
        }}
        .btn-expand:hover {{
            background: #475569;
        }}
        
        @media print {{
            @page {{
                size: letter portrait;
                margin: 10mm 12mm 15mm 12mm;
            }}
            body {{
                background: #ffffff !important;
                color: #0f172a !important;
                font-size: 9.5pt !important;
                line-height: 1.4 !important;
                padding: 0 !important;
            }}
            .container {{
                max-width: 100% !important;
                width: 100% !important;
                margin: 0 !important;
                padding: 0 !important;
            }}
            header {{
                background: #ffffff !important;
                border: 1px solid #cbd5e1 !important;
                box-shadow: none !important;
                padding: 14px !important;
                margin-bottom: 14px !important;
                page-break-after: avoid;
                break-after: avoid;
            }}
            header h1 {{
                color: #0f172a !important;
                font-size: 16pt !important;
            }}
            .header-meta, .header-meta div, .header-meta strong {{
                color: #334155 !important;
            }}
            .no-print, .filter-bar, .btn-toggle, .btn-action, input, select, button {{
                display: none !important;
            }}
            .grid-summary {{
                gap: 10px !important;
                margin-bottom: 14px !important;
                page-break-after: avoid;
                break-after: avoid;
            }}
            .card {{
                background: #ffffff !important;
                color: #0f172a !important;
                border: 1px solid #cbd5e1 !important;
                box-shadow: none !important;
                padding: 12px !important;
                margin-bottom: 14px !important;
                page-break-inside: avoid;
                break-inside: avoid;
            }}
            .card h2 {{
                color: #0f172a !important;
                border-bottom: 1px solid #e2e8f0 !important;
                font-size: 12pt !important;
                margin-bottom: 10px !important;
            }}
            .card-num {{
                font-size: 20pt !important;
            }}
            .card-label {{
                color: #64748b !important;
                font-size: 8.5pt !important;
            }}
            table {{
                width: 100% !important;
                border-collapse: collapse !important;
                font-size: 8.5pt !important;
                margin-bottom: 14px !important;
            }}
            th {{
                background: #f1f5f9 !important;
                color: #334155 !important;
                border: 1px solid #cbd5e1 !important;
                font-size: 8pt !important;
                padding: 6px 8px !important;
            }}
            td {{
                border: 1px solid #cbd5e1 !important;
                color: #0f172a !important;
                padding: 6px 8px !important;
            }}
            tr.finding-row {{
                page-break-inside: avoid !important;
                break-inside: avoid !important;
            }}
            .details-row {{
                display: table-row !important;
                page-break-inside: avoid !important;
                break-inside: avoid !important;
            }}
            .details-pane {{
                background: #ffffff !important;
                border: none !important;
                padding: 6px 0 14px 0 !important;
                margin: 0 !important;
            }}
            .audit-section-card {{
                background: #ffffff !important;
                border: 1px solid #cbd5e1 !important;
                border-radius: 6px !important;
                padding: 12px 16px !important;
                margin-bottom: 12px !important;
                page-break-inside: avoid !important;
                break-inside: avoid !important;
            }}
            .section-badge {{
                background: #e0f2fe !important;
                color: #0369a1 !important;
                border: 1px solid #bae6fd !important;
                border-left: 4px solid #0284c7 !important;
                font-weight: 700 !important;
                font-size: 8pt !important;
                padding: 3px 8px !important;
                margin: 0 0 8px 0 !important;
                display: inline-block !important;
                page-break-after: avoid !important;
                break-after: avoid !important;
            }}
            .audit-section-content {{
                font-size: 8.5pt !important;
                line-height: 1.5 !important;
                color: #0f172a !important;
            }}
            .audit-section-content p {{
                margin-bottom: 6px !important;
                line-height: 1.5 !important;
                color: #0f172a !important;
            }}
            .audit-section-content ul {{
                margin: 4px 0 8px 18px !important;
            }}
            .audit-section-content li {{
                margin-bottom: 3px !important;
            }}
            .audit-section-content strong {{
                color: #1e293b !important;
            }}
            .sub-table {{
                background: #ffffff !important;
                border: 1px solid #cbd5e1 !important;
                font-size: 8pt !important;
                margin: 6px 0 !important;
            }}
            .sub-table th {{
                background: #f8fafc !important;
                color: #475569 !important;
                border: 1px solid #e2e8f0 !important;
                padding: 4px 6px !important;
            }}
            .sub-table td {{
                border: 1px solid #e2e8f0 !important;
                color: #0f172a !important;
                padding: 4px 6px !important;
            }}
            .code-exp {{
                background: #f1f5f9 !important;
                color: #065f46 !important;
                border: 1px solid #cbd5e1 !important;
            }}
            .evidence-box {{
                background: #ffffff !important;
                border: 1px solid #cbd5e1 !important;
                color: #0f172a !important;
                padding: 6px 8px !important;
                margin-bottom: 6px !important;
                page-break-inside: avoid !important;
                break-inside: avoid !important;
            }}
            .evidence-cmd {{
                color: #0369a1 !important;
                font-weight: 700 !important;
                font-size: 8pt !important;
            }}
            .evidence-meta {{
                color: #64748b !important;
                font-size: 7.5pt !important;
            }}
            .evidence-output {{
                background: #f8fafc !important;
                color: #0f172a !important;
                border: 1px solid #cbd5e1 !important;
                padding: 4px 6px !important;
                font-size: 7.5pt !important;
                white-space: pre-wrap !important;
                word-break: break-all !important;
            }}
            .safe-verify-box {{
                background: #f0fdf4 !important;
                border: 1px solid #86efac !important;
                border-left: 4px solid #16a34a !important;
                color: #166534 !important;
                padding: 6px 8px !important;
                font-size: 8pt !important;
            }}
            .remed-section {{
                margin-top: 4px !important;
            }}
            .remed-section pre {{
                background: #fffbeb !important;
                color: #92400e !important;
                border: 1px solid #fde68a !important;
                padding: 4px 6px !important;
                font-size: 7.5pt !important;
            }}
            .risk-compare-box {{
                background: #f1f5f9 !important;
                border: 1px solid #cbd5e1 !important;
                color: #0f172a !important;
                padding: 6px 8px !important;
                margin: 4px 0 !important;
                font-size: 8pt !important;
            }}
            .prereq-container {{
                gap: 8px !important;
                margin: 4px 0 !important;
            }}
            .prereq-col {{
                background: #ffffff !important;
                border: 1px solid #cbd5e1 !important;
                color: #0f172a !important;
                padding: 6px !important;
                font-size: 7.5pt !important;
            }}
            code {{
                background: #f1f5f9 !important;
                color: #0f172a !important;
                border: 1px solid #e2e8f0 !important;
                padding: 1px 3px !important;
                font-size: 8pt !important;
            }}
            .badge {{
                border: 1px solid #94a3b8 !important;
                font-size: 7pt !important;
                padding: 1px 4px !important;
            }}
            .badge-sev-critical {{ background: #fee2e2 !important; color: #991b1b !important; border-color: #f87171 !important; }}
            .badge-sev-high {{ background: #ffedd5 !important; color: #9a3412 !important; border-color: #fb923c !important; }}
            .badge-sev-medium {{ background: #fef9c3 !important; color: #854d0e !important; border-color: #facc15 !important; }}
            .badge-sev-low {{ background: #dbeafe !important; color: #1e40af !important; border-color: #60a5fa !important; }}
            .badge-status-affected {{ background: #fee2e2 !important; color: #991b1b !important; border-color: #ef4444 !important; }}
            .badge-status-potentially-affected {{ background: #fef3c7 !important; color: #92400e !important; border-color: #f59e0b !important; }}
            .badge-status-mitigated {{ background: #f3e8ff !important; color: #6b21a8 !important; border-color: #a855f7 !important; }}
            .badge-status-fixed {{ background: #d1fae5 !important; color: #065f46 !important; border-color: #10b981 !important; }}
            .badge-status-not-affected {{ background: #f1f5f9 !important; color: #475569 !important; border-color: #cbd5e1 !important; }}
            .badge-cisa {{ background: #dc2626 !important; color: #ffffff !important; }}
            .risk-score-circle {{
                background: #ffffff !important;
                color: #0f172a !important;
                border: 2px solid #0284c7 !important;
                width: 28px !important;
                height: 28px !important;
                font-size: 8.5pt !important;
            }}
        }}
    </style>
</head>
<body>
    <div style="background: #1e293b; border-bottom: 2px solid #3b82f6; color: #94a3b8; font-size: 0.75rem; font-weight: 700; letter-spacing: 0.1em; text-align: center; padding: 6px 16px; text-transform: uppercase;">
        {getattr(report.branding, 'classification', 'CONFIDENTIAL')} {f"&bull; Organization: {report.branding.company_name}" if getattr(report, 'branding', None) and report.branding.company_name else ""} {f"&bull; Assessor: {report.branding.assessor_name}" if getattr(report, 'branding', None) and report.branding.assessor_name else ""}
    </div>
    <div class="container">
        <header>
            <div>
                <h1>Linux Security Assessment Report</h1>
                <div class="header-meta">
                    Target Host: <strong>{sys.hostname}</strong> | OS: <strong>{sys.os_name} {sys.os_version} ({sys.architecture})</strong> | Cloud: <strong>{sys.cloud_provider or 'N/A'}</strong>
                </div>
            </div>
            <div style="display: flex; flex-direction: column; align-items: flex-end; gap: 8px;">
                <div class="header-meta" style="text-align: right;">
                    <div>Scan Timestamp: <strong>{report.scan_timestamp}</strong></div>
                    <div>Scanner Engine: <strong>v{report.scanner_version}</strong> ({'Offline Mode' if report.is_offline_mode else 'Live Connected'})</div>
                    <div>Duration: <strong>{summary.duration_seconds}s</strong></div>
                </div>
                <div class="no-print" style="display: flex; gap: 8px; margin-top: 4px;">
                    <button class="btn-action btn-expand" id="btnToggleAll" onclick="toggleAllDetails()">📂 Expand All Sections</button>
                    <button class="btn-action btn-print" onclick="prepareAndPrint()">🖨️ Print / Export PDF</button>
                </div>
            </div>
        </header>

        <div class="grid-summary">
            <div class="card">
                <div class="card-num" style="color: var(--affected);">{summary.affected_count}</div>
                <div class="card-label">Confirmed Affected</div>
            </div>
            <div class="card">
                <div class="card-num" style="color: var(--potential);">{summary.potentially_affected_count}</div>
                <div class="card-label">Potentially Affected</div>
            </div>
            <div class="card">
                <div class="card-num" style="color: var(--mitigated);">{summary.mitigated_count}</div>
                <div class="card-label">Mitigated by Config</div>
            </div>
            <div class="card">
                <div class="card-num" style="color: var(--fixed);">{summary.fixed_count}</div>
                <div class="card-label">Vendor Fixed / Patched</div>
            </div>
            <div class="card">
                <div class="card-num" style="color: #ef4444;">{summary.cisa_kev_count}</div>
                <div class="card-label">CISA Known Exploited</div>
            </div>
        </div>

        <div class="card" style="margin-bottom: 24px;">
            <h2>System & Hardware Identity</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; font-size: 14px;">
                <div><strong>Kernel:</strong> {sys.kernel_version}</div>
                <div><strong>Package Manager:</strong> {sys.package_manager.value.upper()}</div>
                <div><strong>Platform ID:</strong> {sys.platform_id or 'N/A'}</div>
                <div><strong>CPU Model:</strong> {sys.cpu.model_name if sys.cpu else 'Unknown'}</div>
                <div><strong>CPU AVX-512 VBMI:</strong> {'Supported' if (sys.cpu and sys.cpu.has_avx512_vbmi) else 'Not Supported'}</div>
                <div><strong>Virtualization:</strong> {sys.virtualization or 'N/A'}</div>
                <div><strong>Total Packages Installed:</strong> {len(report.packages)}</div>
                <div><strong>Active Services:</strong> {len([s for s in report.services if s.is_running])}</div>
            </div>
        </div>

        <div class="filter-bar">
            <input type="text" id="searchInput" placeholder="Search CVE ID, component (e.g. nginx, java, sudo), or title..." onkeyup="filterTable()">
            <select id="severityFilter" onchange="filterTable()">
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
            </select>
            <select id="statusFilter" onchange="filterTable()">
                <option value="ALL">All Statuses</option>
                <option value="Affected">Affected</option>
                <option value="Potentially affected">Potentially affected</option>
                <option value="Mitigated">Mitigated</option>
                <option value="Fixed">Fixed</option>
                <option value="Not affected">Not affected</option>
            </select>
            <button onclick="resetFilters()">Reset Filters</button>
        </div>

        <div class="card">
            <h2>Evaluated Vulnerabilities & Applicability ({len(findings)})</h2>
            <table id="findingsTable">
                <thead>
                    <tr>
                        <th>Rank</th>
                        <th>CVE & Advisory</th>
                        <th>Component</th>
                        <th>Severity & Scores</th>
                        <th>Status</th>
                        <th>Risk</th>
                        <th>Evidence</th>
                    </tr>
                </thead>
                <tbody>
                    {findings_table_html}
                </tbody>
            </table>
        </div>

        <div class="card" style="margin-top: 24px;">
            <h2>Package Inventory Sample (First 50 of {len(report.packages)})</h2>
            <table>
                <thead>
                    <tr>
                        <th>Package</th>
                        <th>Version</th>
                        <th>Release</th>
                        <th>Arch</th>
                        <th>Vendor</th>
                    </tr>
                </thead>
                <tbody>
                    {pkg_table_html}
                </tbody>
            </table>
        </div>
    </div>

    <script>
        function toggleDetails(cveId) {{
            const row = document.getElementById('details-' + cveId);
            if (row.style.display === 'none' || !row.style.display) {{
                row.style.display = 'table-row';
            }} else {{
                row.style.display = 'none';
            }}
        }}

        function toggleAllDetails() {{
            const btn = document.getElementById('btnToggleAll');
            const rows = document.querySelectorAll('.details-row');
            const isExpanded = btn.getAttribute('data-expanded') === 'true';
            rows.forEach(r => {{
                r.style.display = isExpanded ? 'none' : 'table-row';
            }});
            btn.setAttribute('data-expanded', isExpanded ? 'false' : 'true');
            btn.innerHTML = isExpanded ? '📂 Expand All Sections' : '📁 Collapse All Sections';
        }}

        function prepareAndPrint() {{
            // Automatically expand all detail sections before printing so no sections are hidden
            document.querySelectorAll('.details-row').forEach(r => {{
                r.style.display = 'table-row';
            }});
            window.print();
        }}

        window.onbeforeprint = function() {{
            document.querySelectorAll('.details-row').forEach(r => {{
                r.style.display = 'table-row';
            }});
        }};

        function filterTable() {{
            const search = document.getElementById('searchInput').value.toLowerCase();
            const sev = document.getElementById('severityFilter').value;
            const status = document.getElementById('statusFilter').value;
            const rows = document.querySelectorAll('.finding-row');

            rows.forEach(row => {{
                const cve = row.getAttribute('data-cve').toLowerCase();
                const comp = row.getAttribute('data-comp').toLowerCase();
                const rSev = row.getAttribute('data-sev');
                const rStatus = row.getAttribute('data-status');
                const text = row.innerText.toLowerCase();

                const matchesSearch = !search || text.includes(search) || cve.includes(search) || comp.includes(search);
                const matchesSev = (sev === 'ALL') || (rSev === sev);
                const matchesStatus = (status === 'ALL') || (rStatus === status);

                if (matchesSearch && matchesSev && matchesStatus) {{
                    row.style.display = 'table-row';
                }} else {{
                    row.style.display = 'none';
                    const cveId = row.getAttribute('data-cve');
                    const detailsRow = document.getElementById('details-' + cveId);
                    if (detailsRow) detailsRow.style.display = 'none';
                }}
            }});
        }}

        function resetFilters() {{
            document.getElementById('searchInput').value = '';
            document.getElementById('severityFilter').value = 'ALL';
            document.getElementById('statusFilter').value = 'ALL';
            filterTable();
        }}
    </script>
</body>
</html>
"""
        return html
