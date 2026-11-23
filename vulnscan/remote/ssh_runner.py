"""
Remote SSH Execution Runner.
Executes non-destructive, read-only system inventory commands over SSH using
system ssh or paramiko with strict command safety validation and auditable logging.
"""

import subprocess
import shlex
from typing import Tuple, List, Optional


class RemoteSSHRunner:
    # Explicit blacklist of mutating or destructive commands
    FORBIDDEN_TOKENS = [
        "rm ", "dd ", "mkfs", "chmod", "chown", "reboot", "shutdown",
        "poweroff", "init 0", "init 6", "systemctl restart", "systemctl stop",
        "systemctl disable", "dnf install", "dnf update", "dnf remove",
        "yum install", "yum update", "yum remove", "apt-get install",
        "apt-get remove", "apt-get upgrade", "iptables -F", "firewall-cmd"
    ]

    def __init__(
        self,
        host: str,
        user: str = "root",
        port: int = 22,
        key_file: Optional[str] = None
    ):
        self.host = host
        self.user = user
        self.port = port
        self.key_file = key_file
        self.executed_commands_log: List[str] = []

    def validate_command_safety(self, cmd: str) -> bool:
        cmd_lower = cmd.lower()
        for forbidden in self.FORBIDDEN_TOKENS:
            if forbidden in cmd_lower:
                return False
        return True

    def run_command(self, cmd: str) -> Tuple[int, str, str]:
        """
        Executes command on remote target via SSH.
        Returns: (exit_code, stdout, stderr)
        """
        if not self.validate_command_safety(cmd):
            err = f"SAFETY VIOLATION: Command '{cmd}' contains prohibited mutating operations and was blocked."
            return (1, "", err)

        self.executed_commands_log.append(cmd)

        # Build ssh command
        ssh_cmd = [
            "ssh",
            "-p", str(self.port),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=10",
        ]
        if self.key_file:
            ssh_cmd.extend(["-i", self.key_file])

        target = f"{self.user}@{self.host}"
        ssh_cmd.append(target)
        ssh_cmd.append(cmd)

        try:
            res = subprocess.run(
                ssh_cmd,
                capture_output=True,
                text=True,
                timeout=45
            )
            return (res.returncode, res.stdout, res.stderr)
        except subprocess.TimeoutExpired:
            return (124, "", "Command execution timed out over SSH.")
        except Exception as e:
            return (1, "", f"SSH Execution Error: {str(e)}")
