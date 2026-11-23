"""
Unit tests for configuration analyzers and data sanitizer.
"""

import unittest
from vulnscan.inventory.config_analyzer import ConfigurationAnalyzer
from vulnscan.core.sanitizer import Sanitizer


class TestConfigAnalyzer(unittest.TestCase):
    def test_sanitizer_redaction(self):
        secret_text = "listen 443; ssl_certificate_key /etc/pki/tls/private/server.key; db_password = 'SuperSecretPassword123!';"
        sanitized = Sanitizer.sanitize(secret_text)
        self.assertNotIn("SuperSecretPassword123!", sanitized)
        self.assertIn("[REDACTED_SECRET]", sanitized)

    def test_sanitizer_private_key(self):
        key_text = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3d+w+2/W64jE8nC...
-----END RSA PRIVATE KEY-----"""
        sanitized = Sanitizer.sanitize(key_text)
        self.assertEqual(sanitized, "[REDACTED_PRIVATE_KEY]")

    def test_nginx_http2_enabled(self):
        nginx_conf = """server {
    listen 443 ssl http2;
    server_name example.com;
    ssl_protocols TLSv1.2 TLSv1.3;
}"""
        analyzer = ConfigurationAnalyzer()
        findings = analyzer.analyze_nginx(mock_nginx_t=nginx_conf)
        http2_f = next((f for f in findings if f.directive == "http2"), None)
        self.assertIsNotNone(http2_f)
        self.assertEqual(http2_f.value, "enabled")

    def test_nginx_http2_disabled(self):
        nginx_conf = """server {
    listen 443 ssl;
    server_name example.com;
}"""
        analyzer = ConfigurationAnalyzer()
        findings = analyzer.analyze_nginx(mock_nginx_t=nginx_conf)
        http2_f = next((f for f in findings if f.directive == "http2"), None)
        self.assertIsNotNone(http2_f)
        self.assertEqual(http2_f.value, "disabled")

    def test_jvm_base64_intrinsic_mitigated(self):
        ps_out = "1050 /usr/bin/java -Xms2g -Xmx4g -XX:-UseBase64Intrinsics -jar app.jar"
        analyzer = ConfigurationAnalyzer()
        findings = analyzer.analyze_jvm_flags(mock_ps=ps_out)
        f = next((x for x in findings if "-XX:-UseBase64Intrinsics" in x.directive), None)
        self.assertIsNotNone(f)
        self.assertEqual(f.value, "disabled")


if __name__ == "__main__":
    unittest.main()
