"""
Aegis — Central configuration loaded from environment variables.
Copy .env.example to .env and fill in values before running.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ── LLM Provider (OpenAI-compatible) ──────────────────────────────────────────
# Set OPENAI_BASE_URL to use any OpenAI-compatible backend:
#   OpenAI (default): leave OPENAI_BASE_URL empty
#   Ollama:           http://localhost:11434/v1  (set OPENAI_API_KEY=ollama)
#   LM Studio:        http://localhost:1234/v1   (set OPENAI_API_KEY=lm-studio)
#   vLLM:             http://localhost:8000/v1
#   LocalAI:          http://localhost:8080/v1
#   Groq:             https://api.groq.com/openai/v1
OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
OPENAI_BASE_URL: str = os.getenv("OPENAI_BASE_URL", "")
OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")

# ── Auth / OIDC ───────────────────────────────────────────────────────────────
OIDC_ISSUER: str = os.getenv("OIDC_ISSUER", "")
OIDC_AUDIENCE: str = os.getenv("OIDC_AUDIENCE", "aegis")

# ── Cloud providers ───────────────────────────────────────────────────────────
AWS_ENABLED: bool = os.getenv("AWS_ENABLED", "true").lower() == "true"
AZURE_ENABLED: bool = os.getenv("AZURE_ENABLED", "false").lower() == "true"
GCP_ENABLED: bool = os.getenv("GCP_ENABLED", "false").lower() == "true"

# Azure — requires: pip install azure-identity azure-mgmt-network azure-mgmt-storage
AZURE_SUBSCRIPTION_ID: str = os.getenv("AZURE_SUBSCRIPTION_ID", "")

# GCP — requires: pip install google-cloud-compute
GCP_PROJECT_ID: str = os.getenv("GCP_PROJECT_ID", "")

# ── Network scanning ──────────────────────────────────────────────────────────
# Requires nmap binary installed on the system (apt install nmap / brew install nmap)
# and: pip install python-nmap
NETWORK_SCAN_ENABLED: bool = os.getenv("NETWORK_SCAN_ENABLED", "false").lower() == "true"
NETWORK_SCAN_TARGETS: list[str] = [
    t.strip() for t in os.getenv("NETWORK_SCAN_TARGETS", "127.0.0.1").split(",") if t.strip()
]

# ── Live network flow monitoring (v2.11) ──────────────────────────────
# Requires: pip install psutil
# NETWORK_FLOW_MONITOR_ENABLED=true starts a background thread that captures
# live connections and ships IOC-enriched alerts to ClickHouse.
NETWORK_FLOW_MONITOR_ENABLED: bool = os.getenv("NETWORK_FLOW_MONITOR_ENABLED", "false").lower() == "true"
NETWORK_FLOW_MONITOR_INTERVAL: float = float(os.getenv("NETWORK_FLOW_MONITOR_INTERVAL", "10"))

# ── Host malware scanning (v2.11) ─────────────────────────────────────────
# Requires: pip install yara-python watchdog
# HOST_SCAN_ENABLED=true activates YARA + file integrity monitoring.
# HOST_SCAN_WATCH_DIRS: comma-separated dirs to monitor (default: ~/Downloads,/tmp,/var/tmp)
# HOST_SCAN_WATCH_REALTIME=true starts the watchdog filesystem watcher.
HOST_SCAN_ENABLED: bool = os.getenv("HOST_SCAN_ENABLED", "false").lower() == "true"
HOST_SCAN_WATCH_DIRS: list[str] = [
    d.strip() for d in os.getenv("HOST_SCAN_WATCH_DIRS", "").split(",") if d.strip()
] or None   # type: ignore[assignment]  # None → module uses its own defaults
HOST_SCAN_WATCH_REALTIME: bool = os.getenv("HOST_SCAN_WATCH_REALTIME", "false").lower() == "true"
HOST_SCAN_EXTRA_RULES_DIRS: list[str] = [
    d.strip() for d in os.getenv("HOST_SCAN_EXTRA_RULES_DIRS", "").split(",") if d.strip()
]

# ── Kubernetes scanning (v2.3) ────────────────────────────────────────────────
# Requires: pip install kubernetes
# Connects via in-cluster service account or ~/.kube/config
K8S_ENABLED: bool = os.getenv("K8S_ENABLED", "false").lower() == "true"
K8S_NAMESPACES: str = os.getenv("K8S_NAMESPACES", "")   # comma-separated; empty = all
K8S_CONTEXT: str = os.getenv("K8S_CONTEXT", "")          # kubeconfig context; empty = current

# ── IaC scanning (v2.3) ───────────────────────────────────────────────────────
# Scans Terraform (.tf), CloudFormation (.yaml/.json), and Kubernetes manifests
# for misconfigurations before they reach a cloud environment (shift-left).
IAC_ENABLED: bool = os.getenv("IAC_ENABLED", "false").lower() == "true"
IAC_SCAN_PATHS: str = os.getenv("IAC_SCAN_PATHS", ".")   # comma-separated dirs/files

# ── SIEM integration ──────────────────────────────────────────────────────────
# Transport 1: Generic HTTP Webhook
# Compatible with: Graylog, Wazuh, TheHive, OpenSearch Ingest, any custom listener
SIEM_WEBHOOK_URL: str = os.getenv("SIEM_WEBHOOK_URL", "")

# Transport 2: Syslog (RFC 5424) over UDP / TCP / TCP+TLS
# Compatible with: Graylog, rsyslog, syslog-ng, Wazuh, QRadar, OSSEC, Logstash
SIEM_SYSLOG_HOST: str = os.getenv("SIEM_SYSLOG_HOST", "")
SIEM_SYSLOG_PORT: int = int(os.getenv("SIEM_SYSLOG_PORT", "514"))
SIEM_SYSLOG_PROTOCOL: str = os.getenv("SIEM_SYSLOG_PROTOCOL", "udp")  # udp | tcp | tcp+tls

# Transport 3: CEF (Common Event Format) over Syslog
# Open standard (ArcSight). Compatible with: ArcSight, QRadar, Wazuh, LogRhythm, Splunk*
# Set to true to send CEF instead of plain RFC 5424 syslog when SIEM_SYSLOG_HOST is set.
SIEM_CEF_ENABLED: bool = os.getenv("SIEM_CEF_ENABLED", "false").lower() == "true"

# ── ClickHouse Analytics Backend ──────────────────────────────────────────────
# Unified analytics via ClickHouse — replaces Elasticsearch/OpenSearch.
# Used for CSPM findings indexing, AI telemetry, and cross-product analytics.
CLICKHOUSE_HOST: str = os.getenv("CLICKHOUSE_HOST", "localhost")
CLICKHOUSE_PORT: int = int(os.getenv("CLICKHOUSE_PORT", "9000"))
CLICKHOUSE_DB: str = os.getenv("CLICKHOUSE_DB", "aegis")
CLICKHOUSE_ANALYTICS_ENABLED: bool = os.getenv("CLICKHOUSE_ANALYTICS_ENABLED", "true").lower() == "true"

# Legacy aliases — kept so existing code doesn't break during migration
ELASTICSEARCH_ENABLED: bool = CLICKHOUSE_ANALYTICS_ENABLED  # maps to CH now
ELASTICSEARCH_INDEX_PREFIX: str = os.getenv("ELASTICSEARCH_INDEX_PREFIX", "aegis")

# ── Dashboard Backend ─────────────────────────────────────────────────────────
# Custom ClickHouse-backed dashboard served by Aegis itself.
# DASHBOARD_PORT: port the built-in dashboard server listens on (default 5601)
DASHBOARD_PORT: int = int(os.getenv("DASHBOARD_PORT", "5601"))

# ── Dev / Testing ─────────────────────────────────────────────────────────────
# DEV_MODE=true disables OIDC JWT verification so you can call the API without
# a real identity provider. NEVER enable in production.
DEV_MODE: bool = os.getenv("DEV_MODE", "false").lower() == "true"

# ── Remediation behaviour ─────────────────────────────────────────────────────
# DRY_RUN=true  → AI decides actions, logs what it would do, but makes no changes
# DRY_RUN=false → AI actually executes remediation (requires AUTO_REMEDIATE=true)
DRY_RUN: bool = os.getenv("DRY_RUN", "true").lower() == "true"

# AUTO_REMEDIATE must be explicitly set to true to allow live changes.
# When false, only dry-run analysis and SIEM alerts are permitted.
AUTO_REMEDIATE: bool = os.getenv("AUTO_REMEDIATE", "false").lower() == "true"
# ── Production Safety Guard ────────────────────────────────────────────────────
# IL6 / FedRAMP: DEV_MODE must NEVER be active in production.
# This block terminates the process immediately if DEV_MODE is set
# and the ENVIRONMENT variable indicates a non-development context.
import sys as _sys

_ENVIRONMENT = os.getenv("ENVIRONMENT", "dev").lower()
_PROD_ENVIRONMENTS = {"production", "staging", "prod", "stage", "il2", "il4", "il5", "il6"}

if DEV_MODE and _ENVIRONMENT in _PROD_ENVIRONMENTS:
    print(
        f"FATAL: DEV_MODE=true is set but ENVIRONMENT={_ENVIRONMENT}. "
        "DEV_MODE bypasses all authentication and is prohibited in production. "
        "Unset DEV_MODE or set ENVIRONMENT=dev to proceed.",
        file=_sys.stderr,
    )
    _sys.exit(1)
