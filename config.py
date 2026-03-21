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

# ── Search / Analytics Backend ────────────────────────────────────────────────
# SEARCH_BACKEND: "opensearch" (recommended, Apache 2.0) or "elasticsearch" (Elastic License)
# Requires: pip install opensearch-py   (for OpenSearch)
#        OR pip install elasticsearch   (for Elasticsearch)
SEARCH_BACKEND: str = os.getenv("SEARCH_BACKEND", "opensearch")
ELASTICSEARCH_ENABLED: bool = os.getenv("ELASTICSEARCH_ENABLED", "false").lower() == "true"
ELASTICSEARCH_URL: str = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
ELASTICSEARCH_API_KEY: str = os.getenv("ELASTICSEARCH_API_KEY", "")
ELASTICSEARCH_USERNAME: str = os.getenv("ELASTICSEARCH_USERNAME", "")
ELASTICSEARCH_PASSWORD: str = os.getenv("ELASTICSEARCH_PASSWORD", "")
ELASTICSEARCH_INDEX_PREFIX: str = os.getenv("ELASTICSEARCH_INDEX_PREFIX", "aegis")

# ── Dashboard Backend ─────────────────────────────────────────────────────────
# DASHBOARD_BACKEND: "opensearch" (OpenSearch Dashboards, Apache 2.0) or "kibana"
# DASHBOARD_URL: base URL for the dashboard (OpenSearch Dashboards or Kibana)
DASHBOARD_BACKEND: str = os.getenv("DASHBOARD_BACKEND", "opensearch")
DASHBOARD_URL: str = os.getenv("DASHBOARD_URL", "http://localhost:5601")
DASHBOARD_API_KEY: str = os.getenv("DASHBOARD_API_KEY", "")

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
