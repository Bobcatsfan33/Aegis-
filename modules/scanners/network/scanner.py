"""
Network scanner — port scanning and service enumeration.

Two modes:
  1. nmap mode  (preferred): uses python-nmap + nmap binary for service detection
                              and vuln scripts.
  2. socket mode (fallback): raw socket connections when nmap is unavailable.

Install nmap binary:   apt install nmap  OR  brew install nmap
Install Python binding: pip install python-nmap
Set NETWORK_SCAN_TARGETS in .env (comma-separated IPs/CIDRs/hostnames).
"""

import logging
import socket
from typing import List

from modules.scanners.base import BaseScanner, Finding

logger = logging.getLogger(__name__)

try:
    import nmap as nmap_lib
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# Ports that are dangerous when exposed to untrusted networks.
# Format: port → (service_label, default_severity)
DANGEROUS_PORTS: dict[int, tuple[str, str]] = {
    21:    ("FTP",                    "critical"),
    22:    ("SSH",                    "high"),
    23:    ("Telnet",                 "critical"),
    25:    ("SMTP",                   "medium"),
    53:    ("DNS",                    "medium"),
    80:    ("HTTP (unencrypted)",     "medium"),
    110:   ("POP3",                   "high"),
    135:   ("Windows RPC",            "critical"),
    139:   ("NetBIOS",                "critical"),
    143:   ("IMAP",                   "high"),
    161:   ("SNMP",                   "high"),
    389:   ("LDAP (unencrypted)",     "high"),
    445:   ("SMB",                    "critical"),
    1433:  ("MSSQL",                  "critical"),
    1521:  ("Oracle DB",              "critical"),
    2375:  ("Docker daemon (no TLS)", "critical"),
    3306:  ("MySQL",                  "critical"),
    3389:  ("RDP",                    "critical"),
    5432:  ("PostgreSQL",             "critical"),
    5900:  ("VNC",                    "critical"),
    6379:  ("Redis",                  "critical"),
    8080:  ("HTTP Alt",               "medium"),
    9200:  ("Elasticsearch",          "critical"),
    27017: ("MongoDB",                "critical"),
}


class NetworkScanner(BaseScanner):
    provider = "network"

    def __init__(self, targets: List[str]):
        self.targets = [t.strip() for t in targets if t.strip()]

    def is_available(self) -> bool:
        return bool(self.targets)

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        for target in self.targets:
            logger.info(f"Scanning target: {target}")
            if NMAP_AVAILABLE:
                findings.extend(self._nmap_scan(target))
            else:
                logger.warning("python-nmap not installed — falling back to socket scanner")
                findings.extend(self._socket_scan(target))
        return findings

    # ── nmap scan ─────────────────────────────────────────────────────────────

    def _nmap_scan(self, target: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            nm = nmap_lib.PortScanner()
            # -sV: service version detection
            # --script vuln: run vulnerability scripts
            # -T4: aggressive timing
            # --top-ports 1000: scan most common 1000 ports
            nm.scan(
                hosts=target,
                arguments="-sV --script vuln -T4 --top-ports 1000",
            )

            for host in nm.all_hosts():
                if nm[host].state() != "up":
                    continue

                for proto in nm[host].all_protocols():
                    for port, port_info in nm[host][proto].items():
                        if port_info["state"] != "open":
                            continue

                        service = port_info.get("name", "unknown")
                        product = port_info.get("product", "")
                        version = port_info.get("version", "")
                        svc_label = f"{service} {product} {version}".strip()

                        # Known-dangerous port finding
                        if port in DANGEROUS_PORTS:
                            label, severity = DANGEROUS_PORTS[port]
                            findings.append(Finding(
                                resource=f"{host}:{port}",
                                issue=f"Exposed {label} service ({svc_label})",
                                severity=severity,
                                provider="network",
                                resource_type="open_port",
                                details={
                                    "host": host,
                                    "port": port,
                                    "protocol": proto,
                                    "service": service,
                                    "product": product,
                                    "version": version,
                                },
                                remediation_hint=(
                                    f"Restrict port {port} via firewall rules "
                                    "or disable the service if not required"
                                ),
                            ))

                        # Vulnerability script hits
                        for script_name, script_output in port_info.get("script", {}).items():
                            if "VULNERABLE" in script_output.upper():
                                findings.append(Finding(
                                    resource=f"{host}:{port}",
                                    issue=f"Vulnerability detected by nmap script: {script_name}",
                                    severity="critical",
                                    provider="network",
                                    resource_type="vulnerability",
                                    details={
                                        "host": host,
                                        "port": port,
                                        "script": script_name,
                                        "output": script_output[:500],
                                    },
                                    remediation_hint="Patch or mitigate the identified vulnerability immediately",
                                ))

        except Exception as e:
            logger.error(f"nmap scan failed for {target}: {e}")
            logger.info("Falling back to socket scan")
            findings.extend(self._socket_scan(target))

        return findings

    # ── socket fallback ───────────────────────────────────────────────────────

    def _socket_scan(self, target: str) -> List[Finding]:
        """Basic TCP connect scan — no service detection, no version info."""
        findings: List[Finding] = []
        for port, (label, severity) in DANGEROUS_PORTS.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1.0)
                result = sock.connect_ex((target, port))
                sock.close()
                if result == 0:
                    findings.append(Finding(
                        resource=f"{target}:{port}",
                        issue=f"Port {port} ({label}) is open and reachable",
                        severity=severity,
                        provider="network",
                        resource_type="open_port",
                        details={"host": target, "port": port},
                        remediation_hint=(
                            f"Block port {port} via firewall rules or "
                            "disable the service if not required"
                        ),
                    ))
            except Exception:
                pass
        return findings
