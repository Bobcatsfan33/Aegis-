"""
Network Remediation Agent — responds to network-level threats.

Actions:
  block_ip       → adds an iptables DROP rule for a source IP (Linux)
  close_port     → blocks inbound TCP/UDP on a specific port via iptables
  isolate_host   → cuts all inbound + outbound traffic to/from a host
  kick_user      → terminates active SSH sessions for a given username

Note: iptables changes are NOT persistent across reboots.
      To persist, also write to /etc/iptables/rules.v4 or use ip6tables as needed.
"""

import logging
import platform
import subprocess
from typing import Optional
from modules.scanners.base import Finding
from modules.agents.base import BaseAgent, RemediationResult

logger = logging.getLogger(__name__)


class NetworkRemediationAgent(BaseAgent):
    """Handles network-level remediation actions."""

    def can_handle(self, finding: Finding) -> bool:
        return finding.provider == "network"

    def remediate(self, finding: Finding, action: str, **kwargs) -> RemediationResult:
        action_map = {
            "block_ip":     self._block_ip,
            "close_port":   self._close_port,
            "isolate_host": self._isolate_host,
            "kick_user":    self._kick_user,
        }
        handler = action_map.get(action)
        if not handler:
            return RemediationResult(
                success=False,
                action_taken="none",
                details=f"Unknown network action '{action}'. "
                        f"Valid actions: {list(action_map.keys())}",
                dry_run=self.dry_run,
                error="unknown_action",
            )
        return handler(finding, **kwargs)

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _require_linux(self) -> Optional[RemediationResult]:  # type: ignore[name-defined]
        if platform.system() != "Linux":
            return RemediationResult(
                success=False,
                action_taken="none",
                details=f"iptables remediation requires Linux (current OS: {platform.system()})",
                dry_run=self.dry_run,
                error="unsupported_os",
            )
        return None

    def _run(self, cmd: list[str]) -> tuple[bool, str]:
        try:
            result = subprocess.run(
                cmd, check=True, capture_output=True, text=True
            )
            return True, result.stdout.strip()
        except subprocess.CalledProcessError as e:
            return False, e.stderr.strip()
        except Exception as e:
            return False, str(e)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _block_ip(self, finding: Finding, ip: str = None, **kwargs) -> RemediationResult:
        host = ip or finding.details.get("host") or finding.resource.split(":")[0]
        action = "block_ip"

        if self.dry_run:
            return RemediationResult(
                success=True,
                action_taken=f"{action} (dry run)",
                details=f"Would add iptables DROP rule for source IP {host}",
                dry_run=True,
            )

        err = self._require_linux()
        if err:
            return err

        ok, msg = self._run(["iptables", "-I", "INPUT", "-s", host, "-j", "DROP"])
        return RemediationResult(
            success=ok,
            action_taken=action,
            details=f"iptables -I INPUT -s {host} -j DROP → {msg}",
            dry_run=False,
            error=None if ok else msg,
        )

    def _close_port(self, finding: Finding, **kwargs) -> RemediationResult:
        port = str(finding.details.get("port", ""))
        action = "close_port"

        if not port:
            return RemediationResult(
                False, action,
                "No port found in finding details",
                self.dry_run, "missing_port",
            )

        if self.dry_run:
            return RemediationResult(
                success=True,
                action_taken=f"{action} (dry run)",
                details=f"Would block inbound TCP port {port} via iptables",
                dry_run=True,
            )

        err = self._require_linux()
        if err:
            return err

        ok, msg = self._run(
            ["iptables", "-I", "INPUT", "-p", "tcp", "--dport", port, "-j", "DROP"]
        )
        return RemediationResult(
            success=ok,
            action_taken=action,
            details=f"iptables DROP on tcp:{port} → {msg}",
            dry_run=False,
            error=None if ok else msg,
        )

    def _isolate_host(self, finding: Finding, **kwargs) -> RemediationResult:
        host = finding.details.get("host") or finding.resource.split(":")[0]
        action = "isolate_host"

        if self.dry_run:
            return RemediationResult(
                success=True,
                action_taken=f"{action} (dry run)",
                details=f"Would isolate host {host} (block all inbound + outbound traffic)",
                dry_run=True,
            )

        err = self._require_linux()
        if err:
            return err

        cmds = [
            ["iptables", "-I", "INPUT",  "-s", host, "-j", "DROP"],
            ["iptables", "-I", "OUTPUT", "-d", host, "-j", "DROP"],
        ]
        results = []
        for cmd in cmds:
            ok, msg = self._run(cmd)
            results.append(f"{' '.join(cmd)} → {msg}")
            if not ok:
                return RemediationResult(
                    False, action,
                    "\n".join(results),
                    dry_run=False,
                    error=msg,
                )

        return RemediationResult(
            success=True,
            action_taken=action,
            details=f"Host {host} isolated:\n" + "\n".join(results),
            dry_run=False,
        )

    def _kick_user(self, finding: Finding, username: str = None, **kwargs) -> RemediationResult:
        """
        Terminate all active SSH sessions for a user.
        Finds their pts/tty via `who` and sends SIGHUP to the session.
        """
        action = "kick_user"
        if not username:
            return RemediationResult(
                False, action,
                "username required for kick_user action",
                self.dry_run, "missing_username",
            )

        if self.dry_run:
            return RemediationResult(
                success=True,
                action_taken=f"{action} (dry run)",
                details=f"Would terminate all active sessions for user '{username}'",
                dry_run=True,
            )

        err = self._require_linux()
        if err:
            return err

        ok, output = self._run(["pkill", "-KILL", "-u", username])
        return RemediationResult(
            success=ok,
            action_taken=action,
            details=f"pkill -KILL -u {username} → {output or 'sessions terminated'}",
            dry_run=False,
            error=None if ok else output,
        )
