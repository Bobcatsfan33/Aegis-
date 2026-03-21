"""
SIEM Alert Agent — delivers security findings over open, vendor-neutral protocols.

Supported transports (configure one or more in .env):
  1. Generic HTTP Webhook   — POST JSON to any endpoint
                              Compatible with: Graylog, Wazuh, OSSEC, TheHive,
                              OpenSearch Ingest, Cortex XSOAR, custom listeners
  2. Syslog (RFC 5424)      — UDP or TCP to any syslog-capable server
                              Compatible with: Graylog, rsyslog, syslog-ng,
                              Wazuh, IBM QRadar, OSSEC, Logstash
  3. CEF over Syslog        — Common Event Format (ArcSight standard, open spec)
                              Compatible with: ArcSight, QRadar, Wazuh, Splunk*,
                              LogRhythm, any syslog receiver (*not required)

All three can be active simultaneously. At least one must be configured for
alerts to be delivered.

No proprietary SDKs or vendor-locked protocols are used.
"""

import json
import logging
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import List

import requests

from config import (
    SIEM_CEF_ENABLED,
    SIEM_SYSLOG_HOST,
    SIEM_SYSLOG_PORT,
    SIEM_SYSLOG_PROTOCOL,
    SIEM_WEBHOOK_URL,
)
from modules.scanners.base import Finding
from modules.agents.base import BaseAgent, RemediationResult

logger = logging.getLogger(__name__)

# RFC 5424 severity mapping
_SEVERITY_MAP = {
    "critical": 2,   # CRIT
    "high":     3,   # ERR
    "medium":   4,   # WARNING
    "low":      5,   # NOTICE
    "info":     6,   # INFO
}

# CEF severity: 0 (Low) – 10 (Very-High)
_CEF_SEVERITY_MAP = {
    "critical": 10,
    "high":     7,
    "medium":   5,
    "low":      3,
    "info":     1,
}

APP_NAME = "Aegis"
APP_VERSION = "2.0"


class SIEMAgent(BaseAgent):
    """
    Delivers security findings to SIEM / alerting platforms via open protocols.
    No proprietary vendor SDKs are used.
    """

    def can_handle(self, finding: Finding) -> bool:
        return True  # alerts can be sent for any finding

    def remediate(self, finding: Finding, action: str = "alert", **kwargs) -> RemediationResult:
        if not SIEM_WEBHOOK_URL and not SIEM_SYSLOG_HOST:
            return RemediationResult(
                success=False,
                action_taken="siem_alert",
                details=(
                    "No SIEM transport configured. Set at least one of: "
                    "SIEM_WEBHOOK_URL (generic webhook) or "
                    "SIEM_SYSLOG_HOST (syslog / CEF) in your .env file."
                ),
                dry_run=self.dry_run,
                error="no_siem_configured",
            )

        results: List[RemediationResult] = []

        if SIEM_WEBHOOK_URL:
            results.append(self._send_webhook(finding))

        if SIEM_SYSLOG_HOST:
            if SIEM_CEF_ENABLED:
                results.append(self._send_cef(finding))
            else:
                results.append(self._send_syslog(finding))

        overall_success = any(r.success for r in results)
        combined = " | ".join(r.details for r in results)

        return RemediationResult(
            success=overall_success,
            action_taken="siem_alert",
            details=combined,
            dry_run=self.dry_run,
            error=None if overall_success else "all_siem_transports_failed",
        )

    # ── Transport 1: Generic HTTP Webhook ─────────────────────────────────────

    def _send_webhook(self, finding: Finding) -> RemediationResult:
        """
        POST a JSON payload to any HTTP endpoint.
        Compatible with Graylog HTTP input, Wazuh API, TheHive, custom listeners, etc.
        """
        if self.dry_run:
            return RemediationResult(
                success=True,
                action_taken="webhook (dry run)",
                details=f"Would POST finding to {SIEM_WEBHOOK_URL}",
                dry_run=True,
            )
        try:
            payload = {
                "source":    APP_NAME,
                "version":   APP_VERSION,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "severity":  finding.severity,
                "finding":   finding.to_dict(),
            }
            resp = requests.post(SIEM_WEBHOOK_URL, json=payload, timeout=10)
            resp.raise_for_status()
            return RemediationResult(
                success=True,
                action_taken="webhook",
                details=f"Alert delivered to webhook (HTTP {resp.status_code})",
                dry_run=False,
            )
        except Exception as e:
            logger.error(f"Webhook delivery failed: {e}")
            return RemediationResult(False, "webhook", str(e), False, str(e))

    # ── Transport 2: Syslog (RFC 5424) ────────────────────────────────────────

    def _send_syslog(self, finding: Finding) -> RemediationResult:
        """
        Send an RFC 5424 syslog message via UDP or TCP.
        Compatible with Graylog (syslog input), rsyslog, syslog-ng, Wazuh, QRadar.

        RFC 5424 format:
          <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
        """
        if self.dry_run:
            return RemediationResult(
                success=True,
                action_taken="syslog (dry run)",
                details=f"Would send RFC 5424 syslog to {SIEM_SYSLOG_HOST}:{SIEM_SYSLOG_PORT}",
                dry_run=True,
            )
        try:
            facility = 1       # LOG_USER
            severity = _SEVERITY_MAP.get(finding.severity.lower(), 6)
            priority = (facility * 8) + severity

            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
            hostname  = socket.gethostname()

            # Structured data element: SD-ID="aegis@0"
            sd_params = " ".join([
                f'provider="{finding.provider}"',
                f'severity="{finding.severity}"',
                f'resource_type="{finding.resource_type or "-"}"',
            ])
            sd = f'[aegis@0 {sd_params}]'

            message = finding.issue.replace("\n", " ")[:512]  # syslog msg length limit

            syslog_msg = (
                f"<{priority}>1 {timestamp} {hostname} {APP_NAME} - - "
                f"{sd} {message}"
            ).encode("utf-8")

            self._send_raw(syslog_msg)
            return RemediationResult(
                success=True,
                action_taken="syslog_rfc5424",
                details=(
                    f"Syslog (RFC 5424) sent to "
                    f"{SIEM_SYSLOG_HOST}:{SIEM_SYSLOG_PORT}/{SIEM_SYSLOG_PROTOCOL.upper()}"
                ),
                dry_run=False,
            )
        except Exception as e:
            logger.error(f"Syslog delivery failed: {e}")
            return RemediationResult(False, "syslog_rfc5424", str(e), False, str(e))

    # ── Transport 3: CEF over Syslog ─────────────────────────────────────────

    def _send_cef(self, finding: Finding) -> RemediationResult:
        """
        Send a Common Event Format (CEF) message over syslog.

        CEF is an open specification originally from ArcSight. It is supported by
        QRadar, Wazuh, LogRhythm, OSSEC, and many other SIEMs natively.

        CEF format:
          CEF:Version|Device Vendor|Device Product|Device Version|
              Signature ID|Name|Severity|Extension
        """
        if self.dry_run:
            return RemediationResult(
                success=True,
                action_taken="cef_syslog (dry run)",
                details=(
                    f"Would send CEF event to "
                    f"{SIEM_SYSLOG_HOST}:{SIEM_SYSLOG_PORT}"
                ),
                dry_run=True,
            )
        try:
            cef_severity = _CEF_SEVERITY_MAP.get(finding.severity.lower(), 3)

            # CEF pipe characters in field values must be escaped
            def cef_escape(s: str) -> str:
                return str(s).replace("\\", "\\\\").replace("|", "\\|")

            # CEF extension key=value pairs (no spaces in keys, values escaped)
            ext_pairs = {
                "rt":     str(int(time.time() * 1000)),  # receipt time (epoch ms)
                "src":    finding.resource,
                "cs1":    finding.provider,
                "cs1Label": "CloudProvider",
                "cs2":    finding.resource_type or "-",
                "cs2Label": "ResourceType",
                "cs3":    finding.remediation_hint or "-",
                "cs3Label": "RemediationHint",
                "msg":    finding.issue,
            }
            def _cef_val(v: str) -> str:
                return v.replace("=", "\\=").replace("\n", " ")

            extension = " ".join(
                f"{k}={_cef_val(v)}"
                for k, v in ext_pairs.items()
                if v and v != "-"
            )

            # Signature ID = <provider>:<resource_type>
            sig_id = cef_escape(
                f"{finding.provider}:{finding.resource_type or 'unknown'}"
            )
            cef_name   = cef_escape(finding.issue[:512])
            cef_header = (
                f"CEF:0|{APP_NAME}|CloudSecurityScanner|{APP_VERSION}"
                f"|{sig_id}|{cef_name}|{cef_severity}|"
            )
            cef_msg = (cef_header + extension).encode("utf-8")

            # Wrap in a minimal syslog header
            facility = 1
            priority = (facility * 8) + _SEVERITY_MAP.get(finding.severity.lower(), 6)
            syslog_prefix = f"<{priority}> {APP_NAME}: ".encode("utf-8")

            self._send_raw(syslog_prefix + cef_msg)
            return RemediationResult(
                success=True,
                action_taken="cef_syslog",
                details=(
                    f"CEF event sent to "
                    f"{SIEM_SYSLOG_HOST}:{SIEM_SYSLOG_PORT}/{SIEM_SYSLOG_PROTOCOL.upper()}"
                ),
                dry_run=False,
            )
        except Exception as e:
            logger.error(f"CEF delivery failed: {e}")
            return RemediationResult(False, "cef_syslog", str(e), False, str(e))

    # ── Raw socket sender ─────────────────────────────────────────────────────

    def _send_raw(self, data: bytes) -> None:
        """Send raw bytes to the configured syslog host over UDP or TCP."""
        proto = SIEM_SYSLOG_PROTOCOL.lower()

        if proto == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(data, (SIEM_SYSLOG_HOST, SIEM_SYSLOG_PORT))
            sock.close()

        elif proto in ("tcp", "tcp+tls", "tls"):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((SIEM_SYSLOG_HOST, SIEM_SYSLOG_PORT))

            if proto in ("tcp+tls", "tls"):
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=SIEM_SYSLOG_HOST)

            # RFC 6587 octet-count framing: "<length> <message>"
            framed = f"{len(data)} ".encode("utf-8") + data
            sock.sendall(framed)
            sock.close()

        else:
            raise ValueError(
                f"Unknown syslog protocol '{proto}'. "
                "Use 'udp', 'tcp', or 'tcp+tls'."
            )
