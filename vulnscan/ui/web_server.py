"""
Zero-Dependency Interactive Web Dashboard Server.
Runs an HTTP server delivering an interactive single-page vulnerability management console
with instant scan execution, filtering, evidence view, and multi-format report downloads.
"""

import os
import json
import urllib.parse
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from vulnscan.core.engine import ScanEngine
from vulnscan.inventory.collector import InventoryCollector
from vulnscan.reporting.html_reporter import HtmlReporter
from vulnscan.reporting.json_reporter import JsonReporter, CsvReporter
from vulnscan.reporting.pdf_reporter import PdfReporter


class VulnScanWebHandler(BaseHTTPRequestHandler):
    cached_report = None
    output_dir = "./reports"

    def _get_base_filename(self) -> str:
        report = self.__class__.cached_report
        if not report:
            return "report"
        host = report.system_info.hostname.replace("/", "_").replace(":", "_").replace(" ", "_")
        try:
            ts_clean = report.scan_timestamp.replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts_clean)
            time_part = dt.strftime("%Y%m%d-%H%M%S")
        except Exception:
            time_part = datetime.now().strftime("%Y%m%d-%H%M%S")
        return f"{host}-{time_part}"

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            if self.__class__.cached_report:
                html = HtmlReporter.render_html(self.__class__.cached_report)
            else:
                html = self._render_empty_dashboard()
            self.wfile.write(html.encode("utf-8"))

        elif path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            data = {"has_report": self.__class__.cached_report is not None}
            if self.__class__.cached_report:
                data["summary"] = self.__class__.cached_report.summary.to_dict()
                data["system"] = self.__class__.cached_report.system_info.to_dict()
            self.wfile.write(json.dumps(data).encode("utf-8"))

        elif path == "/download/json":
            if not self.__class__.cached_report:
                self.send_error(404, "No scan report available")
                return
            base_name = self._get_base_filename()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Disposition", f"attachment; filename={base_name}.json")
            self.end_headers()
            self.wfile.write(json.dumps(self.__class__.cached_report.to_dict(), indent=2).encode("utf-8"))

        elif path == "/download/csv":
            if not self.__class__.cached_report:
                self.send_error(404, "No scan report available")
                return
            base_name = self._get_base_filename()
            csv_path = os.path.join(self.output_dir, f"{base_name}.csv")
            os.makedirs(self.output_dir, exist_ok=True)
            CsvReporter.generate(self.__class__.cached_report, csv_path)
            self.send_response(200)
            self.send_header("Content-Type", "text/csv")
            self.send_header("Content-Disposition", f"attachment; filename={base_name}.csv")
            self.end_headers()
            with open(csv_path, "rb") as f:
                self.wfile.write(f.read())

        elif path == "/download/pdf":
            if not self.__class__.cached_report:
                self.send_error(404, "No scan report available")
                return
            base_name = self._get_base_filename()
            pdf_path = os.path.join(self.output_dir, f"{base_name}.pdf")
            os.makedirs(self.output_dir, exist_ok=True)
            PdfReporter.generate(self.__class__.cached_report, pdf_path)
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Disposition", f"attachment; filename={base_name}.pdf")
            self.end_headers()
            with open(pdf_path, "rb") as f:
                self.wfile.write(f.read())

        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/scan":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            params = urllib.parse.parse_qs(body)
            scan_type = params.get("type", ["rocky9"])[0]

            engine = ScanEngine(offline_mode=True)
            if scan_type == "rocky9":
                inv = InventoryCollector.create_rocky9_reference_inventory()
                report = engine.run_scan(prebuilt_inventory=inv)
            else:
                report = engine.run_scan()

            self.__class__.cached_report = report

            # Redirect back to home
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
        else:
            self.send_error(404, "Not Found")

    def _render_empty_dashboard(self) -> str:
        return """<!DOCTYPE html>
<html>
<head>
    <title>Linux Vulnerability Scanner Console</title>
    <style>
        body { font-family: sans-serif; background: #0f172a; color: #fff; padding: 40px; text-align: center; }
        .box { background: #1e293b; max-width: 600px; margin: 40px auto; padding: 30px; border-radius: 12px; }
        button { background: #3b82f6; color: #fff; border: none; padding: 12px 24px; border-radius: 6px; font-size: 16px; cursor: pointer; margin: 10px; }
        button:hover { background: #2563eb; }
    </style>
</head>
<body>
    <div class="box">
        <h1>Linux Vulnerability Scanner Console</h1>
        <p style="color: #94a3b8; margin: 20px 0;">No active scan report loaded in memory. Select a scanning mode below to initiate assessment.</p>
        <form method="POST" action="/api/scan">
            <input type="hidden" name="type" value="rocky9">
            <button type="submit">Run Rocky Linux 9.6 Reference Assessment</button>
        </form>
        <form method="POST" action="/api/scan">
            <input type="hidden" name="type" value="local">
            <button type="submit" style="background: #10b981;">Scan Current Local Host</button>
        </form>
    </div>
</body>
</html>"""


def run_web_server(port: int = 8080, host: str = "0.0.0.0", initial_report: ScanReport = None, output_dir: str = "./reports"):
    VulnScanWebHandler.cached_report = initial_report
    VulnScanWebHandler.output_dir = output_dir
    server_address = (host, port)
    httpd = HTTPServer(server_address, VulnScanWebHandler)
    print(f"[*] Vulnerability Assessment Web Dashboard active at http://{host if host != '0.0.0.0' else 'localhost'}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down web dashboard server.")
        httpd.server_close()
