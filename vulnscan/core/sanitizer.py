"""
Data Sanitizer and Secret Redactor.
Protects sensitive server configurations, passwords, private keys, API tokens,
and connection strings from being logged or exposed in vulnerability reports.
"""

import re
from typing import Optional


class Sanitizer:
    # Common secret patterns
    PATTERNS = [
        # Private Keys
        (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED_PRIVATE_KEY]"),
        # AWS Access Keys
        (re.compile(r"(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"), "[REDACTED_AWS_KEY]"),
        # AWS Secret Keys
        (re.compile(r"(?i)(aws_secret_access_key|aws_session_token)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"), r"\1=[REDACTED_AWS_SECRET]"),
        # Passwords in key-value pairs (nginx, apache, env, configs)
        (re.compile(r"(?i)(password|passwd|pwd|secret|api_key|apikey|auth_token|access_token|private_token|bearer)\s*([=:]|\s+)\s*['\"]?([^'\"\s;,]{3,})['\"]?"), r"\1\2 [REDACTED_SECRET]"),
        # Database URIs with credentials (e.g. postgresql://user:pass@host)
        (re.compile(r"(?i)([a-z0-9+]+://)([^:]+):([^@]+)@"), r"\1\2:[REDACTED_PASSWORD]@"),
        # HTTP Authorization headers
        (re.compile(r"(?i)(Authorization:\s*(Basic|Bearer)\s+)[^\r\n]+"), r"\1[REDACTED_TOKEN]"),
        # SSL Passphrases
        (re.compile(r"(?i)(ssl_password_file|ssl_certificate_key|AuthUserFile)\s+([^\s;]+)"), r"\1 [REDACTED_PATH]"),
    ]

    @classmethod
    def sanitize(cls, text: Optional[str]) -> str:
        """Sanitizes text, replacing any detected credentials, tokens, or private keys with [REDACTED]."""
        if not text:
            return ""
        result = text
        for pattern, replacement in cls.PATTERNS:
            result = pattern.sub(replacement, result)
        return result

    @classmethod
    def sanitize_command_output(cls, cmd: str, output: str, max_length: int = 1000) -> str:
        """Sanitizes output and trims it to a safe evidence window."""
        cleaned = cls.sanitize(output)
        if len(cleaned) > max_length:
            half = max_length // 2
            return cleaned[:half] + "\n... [TRUNCATED FOR REPORT EVIDENCE] ...\n" + cleaned[-half:]
        return cleaned
