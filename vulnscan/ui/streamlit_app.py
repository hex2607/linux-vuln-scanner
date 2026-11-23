"""
Streamlit Web UI for Linux Vulnerability Scanner and Assessment Tool.
Provides an interactive dashboard for initiating scans, filtering findings,
inspecting applicability evidence, and exporting multi-format reports.
"""

import os
import json
from datetime import datetime
try:
    import streamlit as st
except ImportError:
    st = None

from vulnscan.core.engine import ScanEngine
from vulnscan.inventory.collector import InventoryCollector
from vulnscan.reporting.html_reporter import HtmlReporter
from vulnscan.reporting.pdf_reporter import PdfReporter
from vulnscan.reporting.json_reporter import JsonReporter, CsvReporter
from vulnscan.remote.ssh_runner import RemoteSSHRunner


def main():
    if st is None:
        print("Error: Streamlit is not installed. Run 'pip install streamlit' or use 'vulnscan serve' for the built-in zero-dependency UI.")
        return

    st.set_page_config(
        page_title="Linux Vulnerability Scanner & Security Assessment",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    st.title("🛡️ Linux Vulnerability Scanner & Security Assessment")
    st.markdown("Authoritative, evidence-backed vulnerability assessment and applicability analysis for Linux production servers.")

    # Sidebar configuration
    st.sidebar.header("🎯 Assessment Target")
    target_mode = st.sidebar.selectbox(
        "Scan Mode",
        ["Rocky Linux 9.6 Reference Environment", "Local Server", "Remote Server (SSH)"]
    )

    offline_mode = st.sidebar.checkbox("Offline / Restricted Network Mode", value=True)

    remote_host = ""
    remote_user = "root"
    remote_port = 22
    remote_key = ""

    if target_mode == "Remote Server (SSH)":
        remote_host = st.sidebar.text_input("Host / IP", placeholder="192.168.1.100")
        remote_user = st.sidebar.text_input("SSH Username", value="root")
        remote_port = st.sidebar.number_input("SSH Port", value=22, min_value=1, max_value=65535)
        remote_key = st.sidebar.text_input("Private Key Path", placeholder="~/.ssh/id_rsa")

    # Scenarios for reference environment
    ref_scenario = "Default Production"
    if target_mode == "Rocky Linux 9.6 Reference Environment":
        ref_scenario = st.sidebar.selectbox(
            "Scenario Simulation",
            [
                "Default Production (Unpatched NGINX HTTP/2 + OpenJDK AVX-512)",
                "Mitigated NGINX (HTTP/2 Disabled in Config)",
                "Mitigated OpenJDK (JVM Base64 Intrinsic Disabled)",
                "Non-AVX512 Hardware (Older Xeon CPU lacking VBMI)",
                "Vendor Patched (NGINX 1.20.1-14.el9_2.3 & OpenJDK 17.0.9-1.el9)"
            ]
        )

    launch_scan = st.sidebar.button("🚀 Run Vulnerability Assessment", type="primary")

    if "report" not in st.session_state:
        st.session_state.report = None

    if launch_scan:
        with st.spinner("Executing system inventory and evaluating vulnerability applicability..."):
            runner = None
            prebuilt_inv = None

            if target_mode == "Remote Server (SSH)":
                if not remote_host:
                    st.error("Please specify remote host IP or hostname.")
                    return
                ssh_runner = RemoteSSHRunner(
                    host=remote_host, user=remote_user, port=remote_port, key_file=remote_key or None
                )
                runner = ssh_runner.run_command
                engine = ScanEngine(command_runner=runner, offline_mode=offline_mode)
                report = engine.run_scan()

            elif target_mode == "Rocky Linux 9.6 Reference Environment":
                # Configure based on scenario
                if "Mitigated NGINX" in ref_scenario:
                    prebuilt_inv = InventoryCollector.create_rocky9_reference_inventory(nginx_http2_enabled=False)
                elif "Mitigated OpenJDK" in ref_scenario:
                    prebuilt_inv = InventoryCollector.create_rocky9_reference_inventory(jvm_disable_base64_intrinsics=True)
                elif "Non-AVX512" in ref_scenario:
                    prebuilt_inv = InventoryCollector.create_rocky9_reference_inventory(cpu_has_avx512_vbmi=False)
                elif "Vendor Patched" in ref_scenario:
                    prebuilt_inv = InventoryCollector.create_rocky9_reference_inventory(
                        nginx_release="14.el9_2.3", java_version="17.0.9", java_release="1.el9"
                    )
                else:
                    prebuilt_inv = InventoryCollector.create_rocky9_reference_inventory()

                engine = ScanEngine(offline_mode=offline_mode)
                report = engine.run_scan(prebuilt_inventory=prebuilt_inv)
            else:
                engine = ScanEngine(offline_mode=offline_mode)
                report = engine.run_scan()

            st.session_state.report = report
            st.success("Assessment completed successfully!")

    report = st.session_state.report
    if report:
        sys = report.system_info
        summary = report.summary

        # Executive KPI Cards
        st.subheader("📊 Executive Assessment Summary")
        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("Confirmed Affected", summary.affected_count, delta=None)
        col2.metric("Potentially Affected", summary.potentially_affected_count, delta=None)
        col3.metric("Mitigated by Config", summary.mitigated_count, delta=None)
        col4.metric("Vendor Patched / Fixed", summary.fixed_count, delta=None)
        col5.metric("CISA KEV Exploited", summary.cisa_kev_count, delta=None)

        # Host Metadata Banner
        st.info(
            f"**Host:** `{sys.hostname}` | **OS:** {sys.os_name} {sys.os_version} ({sys.architecture}) | "
            f"**Kernel:** `{sys.kernel_version}` | **CPU:** {sys.cpu.model_name if sys.cpu else 'Unknown'} | "
            f"**Scan Duration:** {summary.duration_seconds}s"
        )

        # Filter bar
        col_f1, col_f2, col_f3 = st.columns([2, 1, 1])
        search_query = col_f1.text_input("🔍 Search CVE ID or Component", "")
        sev_filter = col_f2.selectbox("Filter Severity", ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        status_filter = col_f3.selectbox("Filter Status", ["ALL", "Affected", "Potentially affected", "Mitigated", "Fixed", "Not affected"])

        filtered_findings = report.findings
        if search_query:
            filtered_findings = [
                f for f in filtered_findings
                if search_query.lower() in f.cve_id.lower() or search_query.lower() in f.component.lower() or search_query.lower() in f.title.lower()
            ]
        if sev_filter != "ALL":
            filtered_findings = [f for f in filtered_findings if f.severity.value == sev_filter]
        if status_filter != "ALL":
            filtered_findings = [f for f in filtered_findings if f.status.value == status_filter]

        st.subheader(f"📋 Evaluated Vulnerabilities ({len(filtered_findings)})")

        # Table display
        table_data = []
        for f in filtered_findings:
            table_data.append({
                "Rank": f"#{f.priority_rank}",
                "CVE ID": f.cve_id,
                "Component": f.component,
                "Installed": f.installed_version,
                "Fixed Version": f.fixed_version or "N/A",
                "Severity": f.severity.value,
                "CVSS": f.cvss_score or "N/A",
                "Status": f.status.value,
                "Risk Score": f.risk_priority_score,
                "CISA KEV": "🚨 YES" if f.cisa_kev else "NO",
            })
        st.table(table_data)

        # Detailed Finding Inspector
        st.subheader("🔬 Deep-Dive Evidence & Remediation Audit")
        cve_options = [f"{f.cve_id} - {f.component} ({f.status.value})" for f in filtered_findings]
        if cve_options:
            selected_cve_str = st.selectbox("Select CVE to inspect audited evidence", cve_options)
            sel_cve_id = selected_cve_str.split(" - ")[0]
            finding = next(f for f in filtered_findings if f.cve_id == sel_cve_id)

            col_d1, col_d2 = st.columns(2)
            with col_d1:
                st.markdown(f"**Title:** {finding.title}")
                st.markdown(f"**Status:** `{finding.status.value}` (Confidence: {finding.confidence.value})")
                st.markdown(f"**Applicability Conclusion:** {finding.applicability_reason}")
                st.markdown("**Prerequisites Met:**")
                for p in finding.prerequisites_met:
                    st.markdown(f"- ✅ {p}")
                st.markdown("**Prerequisites Not Met:**")
                for p in finding.prerequisites_not_met:
                    st.markdown(f"- ❌ {p}")

            with col_d2:
                st.markdown(f"**Advisory:** `{finding.advisory_source} ({finding.advisory_id})`")
                if finding.remediation_cmd:
                    st.markdown(f"**Remediation Command:**\n```bash\n{finding.remediation_cmd}\n```")
                if finding.verification_cmd:
                    st.markdown(f"**Verification Command:**\n```bash\n{finding.verification_cmd}\n```")
                if finding.mitigation:
                    st.markdown(f"**Mitigation:** {finding.mitigation}")

            st.markdown("#### Audited Cryptographic Evidence")
            for ev in finding.evidence:
                st.text(f"$ {ev.command}")
                st.caption(f"Source: {ev.source_file_or_target} | Interpretation: {ev.interpretation}")
                st.code(ev.output_snippet)

        # Downloads
        st.subheader("📥 Export Professional Reports")
        d_col1, d_col2, d_col3, d_col4 = st.columns(4)

        os.makedirs("./reports", exist_ok=True)
        host = report.system_info.hostname.replace("/", "_").replace(":", "_").replace(" ", "_")
        try:
            ts_clean = report.scan_timestamp.replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts_clean)
            time_part = dt.strftime("%Y%m%d-%H%M%S")
        except Exception:
            time_part = datetime.now().strftime("%Y%m%d-%H%M%S")
        base_name = f"{host}-{time_part}"

        html_path = f"./reports/{base_name}.html"
        pdf_path = f"./reports/{base_name}.pdf"
        json_path = f"./reports/{base_name}.json"
        csv_path = f"./reports/{base_name}.csv"

        HtmlReporter.generate(report, html_path)
        PdfReporter.generate(report, pdf_path)
        JsonReporter.generate(report, json_path)
        CsvReporter.generate(report, csv_path)

        with open(html_path, "r", encoding="utf-8") as f:
            d_col1.download_button("Download HTML Report", f.read(), file_name=f"{base_name}.html", mime="text/html")

        with open(pdf_path, "rb") as f:
            d_col2.download_button("Download PDF Report", f.read(), file_name=f"{base_name}.pdf", mime="application/pdf")

        with open(json_path, "r", encoding="utf-8") as f:
            d_col3.download_button("Download JSON", f.read(), file_name=f"{base_name}.json", mime="application/json")

        with open(csv_path, "r", encoding="utf-8") as f:
            d_col4.download_button("Download CSV", f.read(), file_name=f"{base_name}.csv", mime="text/csv")


if __name__ == "__main__":
    main()
