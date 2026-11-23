"""
Service and Network Port Inventory Collector.
Discovers running systemd units, daemons, background processes, and open listening sockets.
"""

import re
from typing import List, Dict, Optional, Tuple, Callable
from vulnscan.core.models import ServiceInfo, ListeningPort


class ServiceCollector:
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

    def collect_listening_ports(self, mock_output: Optional[str] = None) -> List[ListeningPort]:
        """
        Parses ss -tulpen or netstat -tulpen for listening TCP and UDP ports.
        """
        out = mock_output
        if out is None:
            out = self._run_cmd("ss -tulpen 2>/dev/null || netstat -tulpen 2>/dev/null")

        ports: List[ListeningPort] = []
        if not out:
            return ports

        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("Netid") or line.startswith("Proto") or line.startswith("State"):
                continue

            parts = line.split()
            # Handle ss output format:
            # Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
            if len(parts) >= 5:
                proto = parts[0].lower()
                # Find local address and port
                local_addr_col = None
                for col in parts:
                    if ":" in col and not col.startswith("users:"):
                        local_addr_col = col
                        break

                if local_addr_col:
                    addr_parts = local_addr_col.rsplit(":", 1)
                    addr = addr_parts[0]
                    try:
                        port_num = int(addr_parts[1])
                    except (ValueError, IndexError):
                        continue

                    # Extract process name if present in users:(("nginx",pid=123,fd=6))
                    proc_name = None
                    pid = None
                    m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
                    if m:
                        proc_name = m.group(1)
                        pid = int(m.group(2))

                    ports.append(ListeningPort(
                        protocol=proto,
                        local_address=addr,
                        local_port=port_num,
                        process_name=proc_name,
                        pid=pid
                    ))
        return ports

    def collect_services(self, mock_systemctl: Optional[str] = None) -> List[ServiceInfo]:
        """
        Collects service statuses from systemctl.
        """
        out = mock_systemctl
        if out is None:
            out = self._run_cmd("systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null")

        services: List[ServiceInfo] = []
        if not out:
            return services

        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 4)
            if len(parts) >= 4:
                unit_name = parts[0]
                load_state = parts[1]
                active_state = parts[2]
                sub_state = parts[3]

                clean_name = unit_name.replace(".service", "")
                services.append(ServiceInfo(
                    name=clean_name,
                    load_state=load_state,
                    active_state=active_state,
                    sub_state=sub_state,
                ))
        return services
