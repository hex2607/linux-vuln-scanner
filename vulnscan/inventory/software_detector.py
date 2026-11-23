"""
Software and Runtime Detector.
Discovers runtimes (Java, Python, Node, NGINX, Apache, OpenSSL, Databases, Containers)
installed both through package managers and standalone/bundled in /opt, /usr/local, or running processes.
"""

import re
from typing import List, Dict, Optional, Tuple, Callable
from vulnscan.core.models import SoftwareRuntime


class SoftwareDetector:
    def __init__(self, command_runner: Optional[Callable[[str], Tuple[int, str, str]]] = None):
        self.runner = command_runner

    def _run_cmd(self, cmd: str) -> str:
        if self.runner:
            code, out, _ = self.runner(cmd)
            return out if code == 0 else ""
        try:
            import subprocess
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
            return res.stdout if res.returncode == 0 else ""
        except Exception:
            return ""

    def detect_java(self) -> List[SoftwareRuntime]:
        runtimes: List[SoftwareRuntime] = []
        # Check default java
        out = self._run_cmd("java -version 2>&1")
        if out:
            # Parse version like: openjdk version "17.0.8" or "1.8.0_382"
            match = re.search(r'version\s+"([^"]+)"', out)
            version = match.group(1) if match else "detected"
            binary_path = self._run_cmd("which java 2>/dev/null") or "/usr/bin/java"
            runtimes.append(SoftwareRuntime(
                name="openjdk",
                detected_version=version,
                binary_path=binary_path,
                install_type="system",
                metadata={"full_output": out.strip()}
            ))

        # Check alternative JVM locations
        find_jvms = self._run_cmd("find /usr/lib/jvm /opt /usr/java -maxdepth 3 -name java -type f 2>/dev/null")
        for line in find_jvms.splitlines():
            path = line.strip()
            if path and path != runtimes[0].binary_path if runtimes else True:
                j_out = self._run_cmd(f"{path} -version 2>&1")
                m = re.search(r'version\s+"([^"]+)"', j_out)
                v = m.group(1) if m else "detected"
                runtimes.append(SoftwareRuntime(
                    name="openjdk",
                    detected_version=v,
                    binary_path=path,
                    install_type="standalone",
                    metadata={"full_output": j_out.strip()}
                ))
        return runtimes

    def detect_nginx(self) -> Optional[SoftwareRuntime]:
        # Check standard and custom paths
        for path in ["/usr/sbin/nginx", "/usr/local/nginx/sbin/nginx", "nginx"]:
            out = self._run_cmd(f"{path} -v 2>&1")
            if "nginx version:" in out:
                m = re.search(r"nginx/([0-9.]+)", out)
                v = m.group(1) if m else "unknown"
                # Check modules via -V
                conf_out = self._run_cmd(f"{path} -V 2>&1")
                has_http2 = "--with-http_v2_module" in conf_out
                has_ssl = "--with-http_ssl_module" in conf_out
                return SoftwareRuntime(
                    name="nginx",
                    detected_version=v,
                    binary_path=path,
                    install_type="system",
                    metadata={
                        "version_output": out.strip(),
                        "has_http_v2_module": has_http2,
                        "has_http_ssl_module": has_ssl,
                        "configure_args": conf_out.strip()
                    }
                )
        return None

    def detect_apache(self) -> Optional[SoftwareRuntime]:
        for bin_name in ["httpd", "apache2"]:
            out = self._run_cmd(f"{bin_name} -v 2>&1")
            if "Server version:" in out:
                m = re.search(r"Apache/([0-9.]+)", out)
                v = m.group(1) if m else "unknown"
                return SoftwareRuntime(
                    name="httpd" if bin_name == "httpd" else "apache2",
                    detected_version=v,
                    binary_path=self._run_cmd(f"which {bin_name} 2>/dev/null") or bin_name,
                    install_type="system",
                    metadata={"output": out.strip()}
                )
        return None

    def detect_openssl(self) -> Optional[SoftwareRuntime]:
        out = self._run_cmd("openssl version -a 2>&1")
        if out and "OpenSSL" in out:
            m = re.search(r"OpenSSL\s+([0-9a-z.-]+)", out)
            v = m.group(1) if m else "unknown"
            return SoftwareRuntime(
                name="openssl",
                detected_version=v,
                binary_path=self._run_cmd("which openssl 2>/dev/null") or "/usr/bin/openssl",
                install_type="system",
                metadata={"details": out.strip()}
            )
        return None

    def detect_python(self) -> Optional[SoftwareRuntime]:
        out = self._run_cmd("python3 --version 2>&1")
        if "Python" in out:
            v = out.split()[1] if len(out.split()) > 1 else "unknown"
            return SoftwareRuntime(
                name="python3",
                detected_version=v,
                binary_path=self._run_cmd("which python3 2>/dev/null") or "/usr/bin/python3",
                install_type="system"
            )
        return None

    def detect_containers(self) -> List[SoftwareRuntime]:
        res: List[SoftwareRuntime] = []
        doc = self._run_cmd("docker --version 2>&1")
        if "Docker version" in doc:
            m = re.search(r"version\s+([0-9.]+)", doc)
            v = m.group(1) if m else "detected"
            res.append(SoftwareRuntime(name="docker", detected_version=v, binary_path="/usr/bin/docker", install_type="system"))

        pod = self._run_cmd("podman --version 2>&1")
        if "podman version" in pod:
            m = re.search(r"version\s+([0-9.]+)", pod)
            v = m.group(1) if m else "detected"
            res.append(SoftwareRuntime(name="podman", detected_version=v, binary_path="/usr/bin/podman", install_type="system"))
        return res

    def detect_nodejs(self) -> Optional[SoftwareRuntime]:
        out = self._run_cmd("node --version 2>&1")
        if out and out.strip().startswith("v"):
            v = out.strip().lstrip("v")
            bin_path = self._run_cmd("which node 2>/dev/null") or "/usr/bin/node"
            return SoftwareRuntime(
                name="nodejs",
                detected_version=v,
                binary_path=bin_path,
                install_type="standalone" if "/usr/bin" not in bin_path else "system",
                metadata={"version_output": out.strip()}
            )
        return None

    def detect_unmanaged_processes(self) -> List[SoftwareRuntime]:
        """
        Inspects running processes executing from non-standard directories
        (/opt, /home, /var/www, /tmp, /srv) indicating unmanaged or bundled runtimes.
        """
        import os
        res: List[SoftwareRuntime] = []
        ps_out = self._run_cmd("ps -eo pid,user,args 2>/dev/null")
        if not ps_out:
            return res

        seen_binaries = set()
        suspicious_prefixes = ("/opt/", "/home/", "/var/www/", "/tmp/", "/srv/")

        for line in ps_out.splitlines()[1:]:
            parts = line.strip().split(None, 2)
            if len(parts) >= 3:
                pid, user, args = parts
                cmd_token = args.split()[0] if args else ""
                if cmd_token.startswith(suspicious_prefixes) and cmd_token not in seen_binaries:
                    seen_binaries.add(cmd_token)
                    bin_name = os.path.basename(cmd_token)
                    res.append(SoftwareRuntime(
                        name=bin_name,
                        detected_version="unmanaged-process",
                        binary_path=cmd_token,
                        install_type="standalone",
                        metadata={"pid": pid, "user": user, "full_cmd": args[:120]}
                    ))
        return res

    def detect_all(self, include_deep: bool = False) -> List[SoftwareRuntime]:
        runtimes: List[SoftwareRuntime] = []
        runtimes.extend(self.detect_java())
        ngx = self.detect_nginx()
        if ngx:
            runtimes.append(ngx)
        httpd = self.detect_apache()
        if httpd:
            runtimes.append(httpd)
        ossl = self.detect_openssl()
        if ossl:
            runtimes.append(ossl)
        py = self.detect_python()
        if py:
            runtimes.append(py)
        node = self.detect_nodejs()
        if node:
            runtimes.append(node)
        runtimes.extend(self.detect_containers())
        if include_deep:
            runtimes.extend(self.detect_unmanaged_processes())
        return runtimes
