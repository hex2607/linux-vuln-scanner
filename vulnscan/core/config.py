"""
Configuration Loader for Linux Vulnerability Scanner.
Loads settings from config.yaml, config.yml, or custom config paths.
Implements zero-dependency fallback parsing if PyYAML is not installed.
"""

import os
import json
from typing import Dict, Any, Optional, List
from vulnscan.core.models import ReportBranding


class ConfigLoader:
    """Manages loading and querying scanner configuration settings."""

    DEFAULT_CONFIG_FILES = ["config.yaml", "config.yml"]

    @classmethod
    def _parse_yaml_fallback(cls, content: str) -> Dict[str, Any]:
        """Minimal zero-dependency fallback parser for simple 2-level YAML configs."""
        data: Dict[str, Any] = {}
        curr_section: Optional[str] = None

        for line in content.splitlines():
            # Remove comments
            clean = line.split("#", 1)[0].rstrip()
            if not clean:
                continue

            # Top level section (e.g. "scanner:")
            if not line.startswith(" ") and not line.startswith("\t") and clean.endswith(":"):
                curr_section = clean[:-1].strip()
                data[curr_section] = {}
                continue

            # Sub-key inside section
            if curr_section and ":" in clean:
                k, v = clean.split(":", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                
                # Convert primitives
                val: Any = v
                if v.lower() == "true":
                    val = True
                elif v.lower() == "false":
                    val = False
                elif v.lower() in ("null", "none", "~", ""):
                    val = None
                elif v.isdigit():
                    val = int(v)
                elif v.startswith("[") and v.endswith("]"):
                    # Basic list
                    raw_items = v[1:-1].split(",")
                    val = [item.strip().strip('"').strip("'") for item in raw_items if item.strip()]

                data[curr_section][k] = val

        return data

    @classmethod
    def load(cls, config_path: Optional[str] = None) -> Dict[str, Any]:
        target_path = None
        if config_path:
            if os.path.exists(config_path):
                target_path = config_path
            else:
                return {}
        else:
            for fname in cls.DEFAULT_CONFIG_FILES:
                if os.path.exists(fname):
                    target_path = fname
                    break

        if not target_path:
            return {}

        try:
            try:
                import yaml
                with open(target_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    return data if isinstance(data, dict) else {}
            except ImportError:
                with open(target_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    return cls._parse_yaml_fallback(content)
        except Exception:
            return {}

    @classmethod
    def get_branding(cls, config: Dict[str, Any], overrides: Optional[Dict[str, Any]] = None) -> ReportBranding:
        overrides = overrides or {}
        b_conf = config.get("branding", {})

        company = overrides.get("company") or b_conf.get("company_name")
        assessor = overrides.get("assessor") or b_conf.get("assessor_name")

        classif = overrides.get("classification")
        if (classif is None or classif == "CONFIDENTIAL") and b_conf.get("classification"):
            classification = b_conf["classification"]
        else:
            classification = classif or "CONFIDENTIAL"

        logo = overrides.get("logo") or b_conf.get("company_logo")

        return ReportBranding(
            company_name=company,
            company_logo=logo,
            assessor_name=assessor,
            classification=classification,
        )

    @classmethod
    def get_output_dir(cls, config: Dict[str, Any], override: Optional[str] = None) -> str:
        if override:
            return override
        return config.get("reporting", {}).get("output_dir", "./reports")

    @classmethod
    def get_formats(cls, config: Dict[str, Any], override: Optional[str] = None) -> str:
        if override:
            return override
        fmts = config.get("reporting", {}).get("default_formats", ["html", "pdf", "json", "csv"])
        if isinstance(fmts, list):
            return ",".join(fmts)
        return str(fmts)

    @classmethod
    def get_depth(cls, config: Dict[str, Any], override: Optional[str] = None) -> str:
        if override and override != "standard":
            return override
        return config.get("scanner", {}).get("depth", "standard")
