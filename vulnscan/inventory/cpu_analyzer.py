"""
CPU Capability and Instruction-Set Analyzer.
Detects CPU architecture, vendor, core topology, and instruction-set extensions
(AVX-512, AVX-512 VBMI, AES-NI, SSE) needed to evaluate hardware vulnerability prerequisites.
"""

import os
import re
from typing import Optional, List, Tuple, Callable
from vulnscan.core.models import CpuCapabilities


class CpuAnalyzer:
    def __init__(self, command_runner: Optional[Callable[[str], Tuple[int, str, str]]] = None):
        self.runner = command_runner

    def _read_cpuinfo(self) -> str:
        if self.runner:
            code, out, _ = self.runner("cat /proc/cpuinfo 2>/dev/null")
            return out if code == 0 else ""
        if os.path.exists("/proc/cpuinfo"):
            try:
                with open("/proc/cpuinfo", "r", encoding="utf-8", errors="replace") as f:
                    return f.read()
            except Exception:
                pass
        return ""

    def analyze(self, mock_cpuinfo: Optional[str] = None) -> CpuCapabilities:
        content = mock_cpuinfo or self._read_cpuinfo()
        vendor_id = "Unknown"
        model_name = "Unknown"
        flags: List[str] = []
        cpu_count = 0

        if content:
            for line in content.splitlines():
                line = line.strip()
                if line.startswith("vendor_id"):
                    vendor_id = line.split(":", 1)[1].strip()
                elif line.startswith("model name"):
                    model_name = line.split(":", 1)[1].strip()
                elif line.startswith("processor"):
                    cpu_count += 1
                elif line.startswith("flags") or line.startswith("Features"):
                    raw_flags = line.split(":", 1)[1].strip().split()
                    flags = sorted(list(set(flags + [f.lower() for f in raw_flags])))

        if cpu_count == 0:
            cpu_count = 1

        flag_set = set(flags)
        has_avx512 = any(f.startswith("avx512") for f in flag_set)
        has_avx512_vbmi = "avx512_vbmi" in flag_set or "avx512vbmi" in flag_set
        has_aes_ni = "aes" in flag_set or "aes-ni" in flag_set

        return CpuCapabilities(
            vendor_id=vendor_id,
            model_name=model_name,
            architecture="x86_64" if "lm" in flag_set else "unknown",
            cpu_count=cpu_count,
            flags=flags,
            has_avx512=has_avx512,
            has_avx512_vbmi=has_avx512_vbmi,
            has_aes_ni=has_aes_ni,
        )
