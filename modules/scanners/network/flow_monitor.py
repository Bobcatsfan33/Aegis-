"""
Aegis — Live Network Flow Monitor  (v2.11.0)
============================================

Continuously captures active network connections via psutil (no raw-socket /
root privileges required) and enriches each flow with:

  • process name & PID (who made the connection)
  • I/O byte counters per NIC
  • inline IOC matching (known-bad IPs, C2 beaconing patterns, suspicious ports)
  • MITRE ATT&CK technique tagging
  • NIST 800-53 Rev5 control references (SI-4, CA-7, AU-2, AU-12)

Results are shipped to ClickHouse via the ClickHouseIndexer *and* are
returned as Finding objects so the compliance report generator can score them.

Usage (standalone):
    from modules.scanners.network.flow_monitor import NetworkFlowMonitor
    monitor = NetworkFlowMonitor()
    monitor.start()          # background thread
    ...
    flows = monitor.snapshot()
    findings = monitor.findings_since_last_call()
    monitor.stop()
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from modules.scanners.base import BaseScanner, Finding

logger = logging.getLogger(__name__)

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logger.warning("psutil not installed — NetworkFlowMonitor unavailable. pip install psutil")


# ── IOC / Threat Intelligence ─────────────────────────────────────────────────

# Ports that should never appear in outbound connections from a CSPM host
# mapped to (description, severity, mitre_technique)
SUSPICIOUS_PORTS: Dict[int, tuple] = {
    4444:  ("Metasploit default listener",        "critical", "T1571"),
    1337:  ("Common C2 port",                     "critical", "T1571"),
    31337: ("Back Orifice / elite port",          "critical", "T1571"),
    8888:  ("Common reverse shell / C2",          "high",     "T1571"),
    9001:  ("Tor SOCKS proxy default",            "high",     "T1090.003"),
    9050:  ("Tor SOCKS5 proxy default",           "high",     "T1090.003"),
    6667:  ("IRC C2 channel",                     "critical", "T1071.004"),
    6697:  ("IRC over TLS C2",                    "critical", "T1071.004"),
    65535: ("Max port — often malware",           "high",     "T1571"),
}

# Known malicious / C2 IPs (representative seed list; production should pull
# from a live CTI feed such as abuse.ch, AlienVault OTX, or MISP)
KNOWN_MALICIOUS_IPS: Set[str] = {
    "185.220.101.0",   # Tor exit node
    "192.42.116.0",    # Tor exit
    "94.102.49.0",     # Known C2 range seed
    "198.96.155.0",    # Abuse.ch
    "185.159.157.0",   # Emotet sinkhole (historic)
}

# Beaconing heuristic: if the same (src_pid, dst_ip, dst_port) combination
# appears more than BEACON_THRESHOLD times within BEACON_WINDOW_SECONDS,
# flag it as potential C2 beaconing.
BEACON_THRESHOLD = 8
BEACON_WINDOW_SECONDS = 120


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class NetworkFlow:
    """Single observed TCP/UDP connection snapshot."""
    timestamp: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    state: str
    pid: Optional[int]
    process_name: Optional[str]
    threat_score: int = 0                          # 0-100
    ioc_match: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    nist_controls: List[str] = field(default_factory=list)
    alert: bool = False
    alert_reason: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "@timestamp":       self.timestamp,
            "src_ip":           self.src_ip,
            "src_port":         self.src_port,
            "dst_ip":           self.dst_ip,
            "dst_port":         self.dst_port,
            "protocol":         self.protocol,
            "state":            self.state,
            "pid":              self.pid,
            "process_name":     self.process_name,
            "threat_score":     self.threat_score,
            "ioc_match":        self.ioc_match,
            "mitre_technique":  self.mitre_technique,
            "mitre_tactic":     self.mitre_tactic,
            "nist_controls":    self.nist_controls,
            "alert":            self.alert,
            "alert_reason":     self.alert_reason,
        }


# ── Core monitor ──────────────────────────────────────────────────────────────

class NetworkFlowMonitor(BaseScanner):
    """
    Background monitor that polls active connections every `interval` seconds,
    enriches flows with threat intelligence, and emits Finding objects for any
    suspicious activity.

    NIST 800-53 Rev5 controls addressed:
      SI-4   — System Monitoring
      CA-7   — Continuous Monitoring
      AU-2   — Event Logging
      AU-12  — Audit Record Generation
      SC-7   — Boundary Protection
    """

    provider = "network"

    def __init__(self, interval: float = 10.0, indexer=None, elastic_indexer=None):
        self._interval = interval
        self._indexer = indexer or elastic_indexer  # Optional[ClickHouseIndexer]
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._flow_history: List[NetworkFlow] = []
        self._pending_findings: List[Finding] = []
        # Beaconing counter: {(pid, dst_ip, dst_port): [epoch_timestamps]}
        self._beacon_tracker: Dict[tuple, List[float]] = {}

    def is_available(self) -> bool:
        return PSUTIL_AVAILABLE

    # ── Public API ─────────────────────────────────────────────────────────────

    def start(self) -> bool:
        """Start background monitoring thread. Returns False if psutil missing."""
        if not PSUTIL_AVAILABLE:
            logger.error("psutil required for NetworkFlowMonitor")
            return False
        if self._thread and self._thread.is_alive():
            return True
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._monitor_loop, name="aegis-net-monitor", daemon=True
        )
        self._thread.start()
        logger.info(f"NetworkFlowMonitor started (poll interval={self._interval}s)")
        return True

    def stop(self):
        """Signal the background thread to stop and wait for it."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=self._interval + 2)
        logger.info("NetworkFlowMonitor stopped")

    def snapshot(self) -> List[NetworkFlow]:
        """Return a copy of all flows seen so far (thread-safe)."""
        with self._lock:
            return list(self._flow_history)

    def findings_since_last_call(self) -> List[Finding]:
        """Drain and return accumulated Finding objects (thread-safe)."""
        with self._lock:
            out = list(self._pending_findings)
            self._pending_findings.clear()
        return out

    # ── BaseScanner.scan() compat ──────────────────────────────────────────────

    def scan(self) -> List[Finding]:
        """
        One-shot synchronous scan — collects a single connection snapshot,
        applies threat enrichment, and returns Findings.
        Suitable for CI / scheduled invocations without a background thread.
        """
        if not PSUTIL_AVAILABLE:
            return []
        flows = self._collect_flows()
        findings: List[Finding] = []
        for flow in flows:
            f = self._enrich_flow(flow)
            if f.alert:
                findings.append(self._flow_to_finding(f))
        return findings

    # ── Background loop ────────────────────────────────────────────────────────

    def _monitor_loop(self):
        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception as exc:
                logger.error(f"NetworkFlowMonitor tick error: {exc}")
            self._stop_event.wait(timeout=self._interval)

    def _tick(self):
        flows = self._collect_flows()
        new_findings: List[Finding] = []
        now_epoch = time.time()

        for flow in flows:
            enriched = self._enrich_flow(flow, now_epoch)
            if enriched.alert:
                finding = self._flow_to_finding(enriched)
                new_findings.append(finding)
                self._index_alert(enriched)

        with self._lock:
            self._flow_history.extend(flows)
            # Keep only last 500 flows in memory
            if len(self._flow_history) > 500:
                self._flow_history = self._flow_history[-500:]
            self._pending_findings.extend(new_findings)

        if new_findings:
            logger.warning(
                f"NetworkFlowMonitor: {len(new_findings)} suspicious flows detected"
            )

    # ── Collection ─────────────────────────────────────────────────────────────

    def _collect_flows(self) -> List[NetworkFlow]:
        flows: List[NetworkFlow] = []
        now = datetime.now(timezone.utc).isoformat()

        pid_name_cache: Dict[int, str] = {}

        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            # Fall back to per-process enumeration (lower privilege requirement)
            conns = []
            for proc in psutil.process_iter(["pid", "name", "connections"]):
                try:
                    for c in proc.info.get("connections") or []:
                        c.pid = proc.info["pid"]
                        pid_name_cache[proc.info["pid"]] = proc.info["name"] or "unknown"
                        conns.append(c)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass

        for conn in conns:
            if conn.raddr is None or not conn.raddr:
                continue                         # no remote end — skip listening sockets
            if conn.raddr.ip in ("", "0.0.0.0", "::", "::1", "127.0.0.1"):
                continue                         # loopback / unconnected

            pid = getattr(conn, "pid", None)
            if pid and pid not in pid_name_cache:
                try:
                    pid_name_cache[pid] = psutil.Process(pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pid_name_cache[pid] = "unknown"

            flows.append(NetworkFlow(
                timestamp=now,
                src_ip=conn.laddr.ip if conn.laddr else "",
                src_port=conn.laddr.port if conn.laddr else 0,
                dst_ip=conn.raddr.ip,
                dst_port=conn.raddr.port,
                protocol="tcp" if conn.type == socket.SOCK_STREAM else "udp",
                state=conn.status or "NONE",
                pid=pid,
                process_name=pid_name_cache.get(pid) if pid else None,
                nist_controls=["SI-4", "CA-7", "AU-2"],
            ))

        return flows

    # ── Enrichment ─────────────────────────────────────────────────────────────

    def _enrich_flow(self, flow: NetworkFlow, now_epoch: float = 0.0) -> NetworkFlow:
        dst_ip = flow.dst_ip
        dst_port = flow.dst_port

        # 1. Known malicious IP
        if dst_ip in KNOWN_MALICIOUS_IPS:
            flow.alert = True
            flow.threat_score = 95
            flow.ioc_match = f"known_malicious_ip:{dst_ip}"
            flow.mitre_technique = "T1071.001"
            flow.mitre_tactic = "command-and-control"
            flow.alert_reason = f"Connection to known malicious IP {dst_ip}"
            flow.nist_controls = ["SI-4", "SC-7", "CA-7"]
            return flow

        # 2. Suspicious destination port
        if dst_port in SUSPICIOUS_PORTS:
            desc, severity, technique = SUSPICIOUS_PORTS[dst_port]
            flow.alert = True
            flow.threat_score = 85 if severity == "critical" else 65
            flow.ioc_match = f"suspicious_port:{dst_port}"
            flow.mitre_technique = technique
            flow.mitre_tactic = "command-and-control"
            flow.alert_reason = f"Port {dst_port} — {desc}"
            flow.nist_controls = ["SI-4", "SC-7", "CA-7"]
            return flow

        # 3. Beaconing heuristic (only during live monitoring, not one-shot scan)
        if now_epoch and flow.pid:
            key = (flow.pid, dst_ip, dst_port)
            history = self._beacon_tracker.setdefault(key, [])
            # Prune old entries outside the window
            cutoff = now_epoch - BEACON_WINDOW_SECONDS
            history[:] = [t for t in history if t >= cutoff]
            history.append(now_epoch)

            if len(history) >= BEACON_THRESHOLD:
                flow.alert = True
                flow.threat_score = 70
                flow.ioc_match = f"beaconing:{dst_ip}:{dst_port}"
                flow.mitre_technique = "T1071.001"
                flow.mitre_tactic = "command-and-control"
                flow.alert_reason = (
                    f"Beaconing detected: {len(history)} connections to "
                    f"{dst_ip}:{dst_port} within {BEACON_WINDOW_SECONDS}s "
                    f"(pid={flow.pid} {flow.process_name})"
                )
                flow.nist_controls = ["SI-4", "SC-7", "CA-7", "AU-2"]

        return flow

    # ── Conversion helpers ─────────────────────────────────────────────────────

    def _flow_to_finding(self, flow: NetworkFlow) -> Finding:
        return Finding(
            resource=f"{flow.src_ip}:{flow.src_port} → {flow.dst_ip}:{flow.dst_port}",
            issue=flow.alert_reason or "Suspicious network flow",
            severity="critical" if flow.threat_score >= 85 else "high" if flow.threat_score >= 65 else "medium",
            provider="network",
            resource_type="network_flow",
            details=flow.to_dict(),
            remediation_hint=(
                f"Investigate process '{flow.process_name}' (PID {flow.pid}). "
                "Block the destination via egress firewall rules if malicious activity confirmed."
            ),
            mitre_techniques=[flow.mitre_technique] if flow.mitre_technique else [],
            mitre_tactic=flow.mitre_tactic,
            nist_controls=flow.nist_controls,
            cwe_id="CWE-200",
        )

    def _index_alert(self, flow: NetworkFlow):
        if not self._indexer:
            return
        try:
            self._indexer._index(
                "network_alerts",
                flow.to_dict(),
            )
        except Exception as exc:
            logger.error(f"Failed to index network alert: {exc}")
