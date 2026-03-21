# Aegis

**Autonomous multi-cloud and network security posture management.**

Aegis scans your AWS, Azure, GCP, and network infrastructure for vulnerabilities, then deploys AI-driven agents to remediate them autonomously — patching misconfigurations, blocking IPs, closing ports, sandboxing users, and alerting your SIEM — without waiting for a human in the loop.

---

## How it works

```
Cloud / Network
      │
      ▼
  Scanners  ──────────────────────────────────────────────────────┐
  (AWS, Azure, GCP, nmap)                                         │
      │                                                           │
      │  Findings (severity, resource, issue)                     │
      ▼                                                           │
 AI Orchestrator  ←─── OpenAI / Ollama / vLLM / any OpenAI-     │
  (function-calling     compatible LLM                           │
   agentic loop)                                                  │
      │                                                           │
      │  Dispatches agents                                        │
      ├──▶ CloudAgent    — fix S3, Security Groups, IAM, RDS     │
      ├──▶ NetworkAgent  — block IPs, close ports, isolate hosts │
      └──▶ SIEMAgent     — syslog (RFC 5424), CEF, webhook       │
                                                                  │
      ▼                                                           │
 OpenSearch  ◀──────────────────────────────────────────────────┘
 + Dashboards
```

---

## Features

- **Cloud-agnostic scanning** — AWS (S3, Security Groups, IAM, CloudTrail, RDS), Azure, GCP
- **Network scanning** — nmap + raw socket fallback, 25+ dangerous ports, vulnerability scripts
- **Autonomous remediation** — AI decides which agent to deploy based on finding severity and type
- **LLM-agnostic** — works with OpenAI, Ollama, vLLM, LM Studio, LocalAI, Groq, or any OpenAI-compatible API
- **SIEM-agnostic** — RFC 5424 syslog, CEF over syslog, or generic HTTP webhook (Graylog, Wazuh, QRadar, etc.)
- **Open-source analytics** — OpenSearch + OpenSearch Dashboards (Apache 2.0); falls back to Elasticsearch
- **Safe by default** — `DRY_RUN=true` out of the box; live remediation requires explicit opt-in
- **Two run modes** — CLI (`main.py`) or REST API (`uvicorn api:app`)

---

## Quick start

### 1. Configure

```bash
cp .env.example .env
# Edit .env — at minimum set OPENAI_API_KEY (or OPENAI_BASE_URL for local LLMs)
```

### 2. Install dependencies

```bash
pip install -r requirements.txt

# For network scanning (optional):
# Linux:  sudo apt install nmap
# macOS:  brew install nmap
```

### 3a. Run — CLI

```bash
python main.py                          # scan all enabled providers (dry run)
python main.py --providers aws,network  # scan specific providers
python main.py --live                   # live remediation (requires AUTO_REMEDIATE=true)
```

### 3b. Run — REST API

```bash
uvicorn api:app --host 0.0.0.0 --port 8000 --reload
```

| Endpoint | Description |
|---|---|
| `GET /` | Health check |
| `POST /scan` | Start an async scan (returns `scan_id`) |
| `GET /scan/{scan_id}` | Poll results |
| `GET /scans` | List all scans |
| `GET /docs` | Interactive API docs (Swagger UI) |

### 3c. Run — Full stack (Docker Compose)

```bash
docker compose up -d

# First-time: set up OpenSearch indices and dashboard
docker compose exec aegis python -m modules.analytics.kibana_setup
```

Spins up: **Aegis API** on `:8000` · **OpenSearch** on `:9200` · **OpenSearch Dashboards** on `:5601`

---

## Configuration

All config is via environment variables (copy `.env.example` to `.env`).

| Variable | Default | Description |
|---|---|---|
| `OPENAI_API_KEY` | — | API key for your LLM provider |
| `OPENAI_BASE_URL` | _(OpenAI)_ | Override for Ollama, vLLM, LocalAI, etc. |
| `OPENAI_MODEL` | `gpt-4o-mini` | Model name |
| `AWS_ENABLED` | `true` | Enable AWS scanner |
| `AZURE_ENABLED` | `false` | Enable Azure scanner |
| `GCP_ENABLED` | `false` | Enable GCP scanner |
| `NETWORK_SCAN_ENABLED` | `false` | Enable nmap network scanner |
| `NETWORK_SCAN_TARGETS` | `127.0.0.1` | Comma-separated IPs / CIDRs |
| `DRY_RUN` | `true` | Log actions without executing them |
| `AUTO_REMEDIATE` | `false` | Must be `true` to allow live changes |
| `ELASTICSEARCH_ENABLED` | `false` | Index findings to OpenSearch / Elasticsearch |
| `SEARCH_BACKEND` | `opensearch` | `opensearch` or `elasticsearch` |
| `SIEM_SYSLOG_HOST` | — | Syslog destination (RFC 5424 / CEF) |
| `SIEM_WEBHOOK_URL` | — | HTTP webhook for SIEM alerts |
| `DEV_MODE` | `false` | Skip JWT auth for local development |

---

## Sandboxed testing

The remediation agents use `iptables`, `pkill`, and raw sockets. To test live remediation safely, use the included Vagrantfile to spin up an isolated Ubuntu VM:

```bash
vagrant up                        # provision VM (~5 min first time)
vagrant snapshot save baseline    # snapshot before destructive tests
vagrant ssh                       # SSH in and run Aegis
vagrant snapshot restore baseline # wipe all changes back to clean state
vagrant destroy                   # discard VM entirely
```

---

## Architecture

```
aegis/
├── api.py                        # FastAPI REST API
├── main.py                       # CLI entry point
├── auth.py                       # OIDC / JWT verification
├── config.py                     # All config from environment variables
├── modules/
│   ├── scanners/
│   │   ├── base.py               # Finding dataclass + BaseScanner ABC
│   │   ├── aws/scanner.py        # S3, Security Groups, IAM, CloudTrail, RDS
│   │   ├── azure/scanner.py      # Azure (stub — extend as needed)
│   │   ├── gcp/scanner.py        # GCP (stub — extend as needed)
│   │   └── network/scanner.py    # nmap / raw socket scanner
│   ├── agents/
│   │   ├── base.py               # BaseAgent + RemediationResult
│   │   ├── orchestrator.py       # AI agentic loop (function-calling)
│   │   ├── cloud_agent.py        # AWS / Azure / GCP remediations
│   │   ├── network_agent.py      # iptables, pkill, port blocking
│   │   └── siem_agent.py         # Syslog RFC 5424, CEF, webhook
│   └── analytics/
│       ├── elastic.py            # OpenSearch / Elasticsearch indexer
│       └── kibana_setup.py       # Dashboard bootstrap script
├── Dockerfile                    # Multi-stage production image
├── docker-compose.yml            # Full stack (app + OpenSearch + Dashboards)
├── Vagrantfile                   # Isolated VM for live remediation testing
└── requirements.txt
```

---

## Deployment

**Development:** `DEV_MODE=true` + `DRY_RUN=true` (default) — no auth, no changes.

**Staging:** Vagrant VM or Docker Compose with `DRY_RUN=true`.

**Production:** Docker Compose or Kubernetes. Set `DEV_MODE=false`, configure `OIDC_ISSUER` with your identity provider (Auth0, Okta, Keycloak, Cognito), and only enable `AUTO_REMEDIATE=true` after validating in staging.

---

## License

MIT
