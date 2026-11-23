"""
Service Configuration Analyzer.
Performs in-depth analysis of service configurations (NGINX, Apache, OpenSSL, Java runtime flags)
to evaluate prerequisite applicability conditions for vulnerabilities while strictly sanitizing secrets.
"""

import re
from typing import List, Dict, Optional, Tuple, Callable
from vulnscan.core.models import ConfigurationFinding
from vulnscan.core.sanitizer import Sanitizer


class ConfigurationAnalyzer:
    def __init__(self, command_runner: Optional[Callable[[str], Tuple[int, str, str]]] = None):
        self.runner = command_runner

    def _run_cmd(self, cmd: str) -> str:
        if self.runner:
            code, out, _ = self.runner(cmd)
            return out if code == 0 else ""
        try:
            import subprocess
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20)
            return res.stdout if res.returncode == 0 else ""
        except Exception:
            return ""

    def analyze_nginx(self, mock_nginx_t: Optional[str] = None) -> List[ConfigurationFinding]:
        """
        Evaluates NGINX configuration using nginx -T.
        Checks for HTTP/2 activation, SSL configuration, and reverse proxy settings.
        Redacts all sensitive values.
        """
        findings: List[ConfigurationFinding] = []
        conf_dump = mock_nginx_t or self._run_cmd("nginx -T 2>/dev/null")
        if not conf_dump:
            return findings

        # Check HTTP/2 configuration
        # Pattern 1: listen 443 ssl http2;
        # Pattern 2: http2 on; (NGINX 1.25.1+)
        has_http2_listen = bool(re.search(r"listen\s+[^;]*\bhttp2\b[^;]*;", conf_dump))
        has_http2_directive = bool(re.search(r"\bhttp2\s+on\s*;", conf_dump))

        if has_http2_listen or has_http2_directive:
            raw = "[MATCHED] listen ... http2;" if has_http2_listen else "[MATCHED] http2 on;"
            findings.append(ConfigurationFinding(
                service_name="nginx",
                config_file="/etc/nginx/nginx.conf",
                directive="http2",
                value="enabled",
                security_relevance="HTTP/2 protocol enabled; triggers HTTP/2 protocol CVE prerequisites (e.g. Rapid Reset CVE-2023-44487, CVE-2026-123633, CVE-2026-123007)",
                raw_snippet=raw
            ))
        else:
            findings.append(ConfigurationFinding(
                service_name="nginx",
                config_file="/etc/nginx/nginx.conf",
                directive="http2",
                value="disabled",
                security_relevance="HTTP/2 is not configured on any listening server block.",
                raw_snippet="http2 not found in listen directives"
            ))

        # Check TLS protocols
        tls_match = re.search(r"ssl_protocols\s+([^;]+);", conf_dump)
        if tls_match:
            protocols = tls_match.group(1).strip()
            findings.append(ConfigurationFinding(
                service_name="nginx",
                config_file="/etc/nginx/nginx.conf",
                directive="ssl_protocols",
                value=protocols,
                security_relevance=f"Configured TLS protocols: {protocols}",
                raw_snippet=Sanitizer.sanitize(tls_match.group(0))
            ))

        # Check reverse proxy directives
        if "proxy_pass" in conf_dump:
            findings.append(ConfigurationFinding(
                service_name="nginx",
                config_file="/etc/nginx/nginx.conf",
                directive="proxy_pass",
                value="configured",
                security_relevance="NGINX functions as a reverse proxy/load balancer.",
                raw_snippet="proxy_pass directive found"
            ))

        return findings

    def analyze_apache(self, mock_mods: Optional[str] = None) -> List[ConfigurationFinding]:
        findings: List[ConfigurationFinding] = []
        mods = mock_mods or self._run_cmd("httpd -M 2>/dev/null || apache2ctl -M 2>/dev/null")
        if mods:
            if "http2_module" in mods:
                findings.append(ConfigurationFinding(
                    service_name="httpd",
                    config_file="httpd.conf",
                    directive="LoadModule",
                    value="mod_http2",
                    security_relevance="HTTP/2 module loaded in Apache.",
                    raw_snippet="http2_module (shared)"
                ))
            if "ssl_module" in mods:
                findings.append(ConfigurationFinding(
                    service_name="httpd",
                    config_file="httpd.conf",
                    directive="LoadModule",
                    value="mod_ssl",
                    security_relevance="SSL module loaded in Apache.",
                    raw_snippet="ssl_module (shared)"
                ))
        return findings

    def analyze_jvm_flags(self, mock_ps: Optional[str] = None) -> List[ConfigurationFinding]:
        """
        Inspects running JVM command line arguments to detect intrinsic flags,
        such as UseAVX, UseBase64Intrinsics, UnlockDiagnosticVMOptions.
        """
        findings: List[ConfigurationFinding] = []
        ps_out = mock_ps or self._run_cmd("ps -eo pid,args | grep -i java | grep -v grep 2>/dev/null")
        if not ps_out:
            return findings

        for line in ps_out.splitlines():
            line = Sanitizer.sanitize(line.strip())
            if not line:
                continue

            # Check Base64 intrinsics
            if "-XX:-UseBase64Intrinsics" in line:
                findings.append(ConfigurationFinding(
                    service_name="java",
                    config_file="jvm_arguments",
                    directive="-XX:-UseBase64Intrinsics",
                    value="disabled",
                    security_relevance="Base64 intrinsics explicitly disabled. Mitigates CVE-2026-114938.",
                    raw_snippet="-XX:-UseBase64Intrinsics"
                ))
            elif "-XX:+UseBase64Intrinsics" in line:
                findings.append(ConfigurationFinding(
                    service_name="java",
                    config_file="jvm_arguments",
                    directive="-XX:+UseBase64Intrinsics",
                    value="enabled",
                    security_relevance="Base64 intrinsics explicitly enabled on JVM.",
                    raw_snippet="-XX:+UseBase64Intrinsics"
                ))
            else:
                findings.append(ConfigurationFinding(
                    service_name="java",
                    config_file="jvm_arguments",
                    directive="UseBase64Intrinsics",
                    value="default_enabled",
                    security_relevance="Base64 intrinsics active by default on modern x86_64 JVMs.",
                    raw_snippet="default JVM intrinsic settings"
                ))

            # Check AVX flags
            avx_m = re.search(r"-XX:UseAVX=(\d+)", line)
            if avx_m:
                val = avx_m.group(1)
                findings.append(ConfigurationFinding(
                    service_name="java",
                    config_file="jvm_arguments",
                    directive="-XX:UseAVX",
                    value=val,
                    security_relevance=f"JVM AVX constraint set to {val} (AVX-512 disabled if < 3).",
                    raw_snippet=f"-XX:UseAVX={val}"
                ))

        return findings

    def analyze_sshd(self, mock_output: Optional[str] = None) -> List[ConfigurationFinding]:
        """
        Audits OpenSSH daemon configuration using 'sshd -T' or /etc/ssh/sshd_config.
        Checks for RootLogin, PasswordAuthentication, and LoginGraceTime (RegreSSHion CVE-2024-6387).
        """
        findings: List[ConfigurationFinding] = []
        out = mock_output or self._run_cmd("sshd -T 2>/dev/null")
        if not out:
            return findings

        # Check LoginGraceTime (CVE-2024-6387)
        lg_m = re.search(r"^logingracetime\s+(\d+)", out, re.MULTILINE | re.IGNORECASE)
        if lg_m:
            val = lg_m.group(1)
            findings.append(ConfigurationFinding(
                service_name="sshd",
                config_file="/etc/ssh/sshd_config",
                directive="LoginGraceTime",
                value=val,
                security_relevance=f"LoginGraceTime set to {val}s. If non-zero and OpenSSH is unpatched, triggers RegreSSHion (CVE-2024-6387) race condition window.",
                raw_snippet=f"logingracetime {val}"
            ))

        # Check PermitRootLogin
        pr_m = re.search(r"^permitrootlogin\s+(\S+)", out, re.MULTILINE | re.IGNORECASE)
        if pr_m:
            val = pr_m.group(1).lower()
            findings.append(ConfigurationFinding(
                service_name="sshd",
                config_file="/etc/ssh/sshd_config",
                directive="PermitRootLogin",
                value=val,
                security_relevance=f"PermitRootLogin is '{val}'. 'no' or 'prohibit-password' protects against brute-force root access.",
                raw_snippet=f"permitrootlogin {val}"
            ))

        # Check PasswordAuthentication
        pa_m = re.search(r"^passwordauthentication\s+(\S+)", out, re.MULTILINE | re.IGNORECASE)
        if pa_m:
            val = pa_m.group(1).lower()
            findings.append(ConfigurationFinding(
                service_name="sshd",
                config_file="/etc/ssh/sshd_config",
                directive="PasswordAuthentication",
                value=val,
                security_relevance=f"PasswordAuthentication is '{val}'. Key-based authentication ('no') is recommended.",
                raw_snippet=f"passwordauthentication {val}"
            ))

        return findings

    def analyze_sysctl(self, mock_output: Optional[str] = None) -> List[ConfigurationFinding]:
        """
        Audits key Linux kernel runtime parameters affecting privilege escalation and network security.
        """
        findings: List[ConfigurationFinding] = []
        out = mock_output or self._run_cmd("sysctl -a 2>/dev/null")
        if not out:
            return findings

        targets = {
            "kernel.unprivileged_userns_clone": "Disables unprivileged user namespaces; mitigates local privilege escalation exploits.",
            "net.ipv4.ip_forward": "IPv4 packet forwarding. Should be 0 on non-router hosts to prevent routing tampering.",
            "fs.protected_regular": "Restricts writing to common world-writable directory files; protects against link attacks.",
            "kernel.kptr_restrict": "Restricts exposure of kernel pointers in /proc to unprivileged users."
        }

        for param, desc in targets.items():
            pattern = rf"^{re.escape(param)}\s*=\s*(\d+)"
            m = re.search(pattern, out, re.MULTILINE)
            if m:
                val = m.group(1)
                findings.append(ConfigurationFinding(
                    service_name="kernel_sysctl",
                    config_file="/etc/sysctl.conf",
                    directive=param,
                    value=val,
                    security_relevance=f"{desc} (Current value: {val})",
                    raw_snippet=f"{param} = {val}"
                ))

        return findings

    def analyze_all(self, include_deep: bool = False) -> List[ConfigurationFinding]:
        findings: List[ConfigurationFinding] = []
        findings.extend(self.analyze_nginx())
        findings.extend(self.analyze_apache())
        findings.extend(self.analyze_jvm_flags())
        if include_deep:
            findings.extend(self.analyze_sshd())
            findings.extend(self.analyze_sysctl())
        return findings
