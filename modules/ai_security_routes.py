"""
AegisAI API Routes — v3.0.0

AI Security endpoints for the AegisAI layer.  Designed to be mounted onto the
existing Aegis FastAPI app via:

    from modules.ai_security_routes import ai_security_router
    app.include_router(ai_security_router)

Endpoints:
  POST /api/ai/discover        → Run AI asset discovery scan (ANALYST+)
  GET  /api/ai/assets          → List discovered AI assets (ANALYST+)
  POST /api/ai/redteam         → Run automated red team attacks (ADMIN+)
  GET  /api/ai/redteam/{id}    → Get red team run results (ANALYST+)
  POST /api/ai/guardrails      → Evaluate content against guardrails (ANALYST+)
  POST /api/ai/policy/evaluate → Evaluate event against policy engine (ANALYST+)
  GET  /api/ai/policy/rules    → List all policy rules (ANALYST+)
  GET  /api/ai/telemetry/stats → Telemetry engine status (ADMIN+)
  GET  /api/ai/telemetry/query → Run analytics query (ANALYST+)
  GET  /api/ai/connectors      → List registered LLM connectors (ANALYST+)
  GET  /api/ai/dashboard       → Unified AegisAI dashboard summary (ANALYST+)
"""

import logging
import os
import uuid
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from modules.security.rbac import Role, require_role
from modules.security.audit_log import AuditEventType, AuditOutcome, log_event

from modules.discovery import DiscoveryEngine, AIAsset
from modules.redteam import RedTeamEngine, AttackResult, AttackCategory
from modules.guardrails import GuardrailsEngine, GuardrailVerdict
from modules.policy import PolicyEngine, RiskAssessment
from modules.telemetry import TelemetryEngine, AIEvent, EventType
from modules.connectors import ConnectorRegistry

logger = logging.getLogger("aegis.ai_security")

# ── Router ────────────────────────────────────────────────────────────

ai_security_router = APIRouter(prefix="/api/ai", tags=["AegisAI"])

# ── Singletons (initialized at import; started properly in lifespan) ──

_connector_registry = ConnectorRegistry()
_discovery_engine = DiscoveryEngine()
_guardrails_engine = GuardrailsEngine()
_policy_engine = PolicyEngine()
_telemetry_engine = TelemetryEngine()

# Red team run results (in-memory; replace with Redis/DB for prod)
_redteam_results: Dict[str, Dict[str, Any]] = {}


def initialize_ai_security():
    """Called from app startup to configure AI security modules."""
    # Register LLM connectors from environment
    _connector_registry.register_from_env()

    # Configure policy engine with env-based settings
    approved_models = os.getenv("AEGIS_APPROVED_MODELS", "").split(",")
    approved_models = [m.strip() for m in approved_models if m.strip()]
    approved_providers = os.getenv("AEGIS_APPROVED_PROVIDERS", "").split(",")
    approved_providers = [p.strip() for p in approved_providers if p.strip()]

    if approved_models:
        _policy_engine.configure(approved_models=approved_models)
    if approved_providers:
        _policy_engine.configure(approved_providers=approved_providers)

    max_tokens = int(os.getenv("AEGIS_MAX_TOKENS_PER_REQUEST", "50000"))
    max_cost = float(os.getenv("AEGIS_MAX_COST_PER_REQUEST", "1.0"))
    _policy_engine.configure(
        max_tokens_per_request=max_tokens,
        max_cost_per_request_usd=max_cost,
    )

    # Start telemetry
    _telemetry_engine.start()

    logger.info("AI Security modules initialized (connectors=%s)", _connector_registry.list_providers())


def shutdown_ai_security():
    """Called from app shutdown to gracefully stop AI security modules."""
    _telemetry_engine.stop()


# ── Pydantic Models ───────────────────────────────────────────────────

class DiscoverRequest(BaseModel):
    scan_env: bool = True
    scan_network: bool = True
    scan_localhost: bool = True
    network_targets: Optional[List[str]] = None


class RedTeamRequest(BaseModel):
    categories: Optional[List[str]] = None
    custom_attacks: Optional[List[Dict[str, Any]]] = None
    target_model: Optional[str] = None
    target_provider: Optional[str] = None


class GuardrailRequest(BaseModel):
    content: str
    direction: str = "input"    # "input" or "output"


class PolicyEvalRequest(BaseModel):
    model: Optional[str] = None
    provider: Optional[str] = None
    prompt: Optional[str] = None
    response: Optional[str] = None
    total_tokens: int = 0
    cost_usd: float = 0.0
    data_classification: Optional[str] = None
    requests_in_window: int = 0
    event_type: str = "ai_request"


# ── Discovery Endpoints ──────────────────────────────────────────────

@ai_security_router.post("/discover", dependencies=[Depends(require_role(Role.ANALYST))])
async def discover_assets(req: DiscoverRequest):
    """Run AI asset discovery scan."""
    engine = DiscoveryEngine(
        scan_env=req.scan_env,
        scan_network=req.scan_network,
        scan_localhost=req.scan_localhost,
        network_targets=req.network_targets,
    )
    assets = engine.scan()

    # Log to telemetry
    _telemetry_engine.log(AIEvent(
        event_type=EventType.DISCOVERY,
        source="discovery_engine",
        severity="info",
        data={"asset_count": len(assets)},
    ))

    # Audit log
    log_event(
        AuditEventType.SCAN,
        AuditOutcome.SUCCESS,
        detail={"type": "ai_discovery", "assets_found": len(assets)},
    )

    return {
        "assets": [a.to_dict() for a in assets],
        "summary": engine.summary(assets),
    }


@ai_security_router.get("/assets", dependencies=[Depends(require_role(Role.ANALYST))])
async def list_assets():
    """Run a quick discovery and return asset inventory."""
    assets = _discovery_engine.scan()
    return {
        "assets": [a.to_dict() for a in assets],
        "summary": _discovery_engine.summary(assets),
    }


# ── Red Team Endpoints ───────────────────────────────────────────────

@ai_security_router.post("/redteam", dependencies=[Depends(require_role(Role.ADMIN))])
async def run_redteam(req: RedTeamRequest):
    """
    Run automated red team attack simulation.
    Requires ADMIN role due to active probing.
    """
    # Parse categories
    categories = None
    if req.categories:
        try:
            categories = [AttackCategory(c) for c in req.categories]
        except ValueError as e:
            raise HTTPException(400, f"Invalid attack category: {e}")

    # Get LLM connector
    llm = None
    if req.target_provider:
        llm = _connector_registry.get(req.target_provider)
    if not llm:
        llm = _connector_registry.get_default()

    engine = RedTeamEngine(
        llm_connector=llm,
        categories=categories,
        custom_attacks=req.custom_attacks,
    )
    results = engine.run_all()
    summary = engine.summary(results)

    # Store results
    run_id = str(uuid.uuid4())[:8]
    _redteam_results[run_id] = {
        "results": [r.to_dict() for r in results],
        "summary": summary,
    }

    # Telemetry for each attack
    for r in results:
        _telemetry_engine.log(AIEvent(
            event_type=EventType.REDTEAM,
            source="redteam_engine",
            severity=r.risk_level.value if r.risk_level.value != "none" else "info",
            data=r.to_dict(),
            risk_score=r.score,
        ))

    # Audit log
    log_event(
        AuditEventType.SCAN,
        AuditOutcome.SUCCESS,
        detail={
            "type": "ai_redteam",
            "run_id": run_id,
            "attacks": len(results),
            "succeeded": summary["attacks_succeeded"],
            "resilience": summary["resilience_score"],
        },
    )

    return {"run_id": run_id, "summary": summary}


@ai_security_router.get("/redteam/{run_id}", dependencies=[Depends(require_role(Role.ANALYST))])
async def get_redteam_results(run_id: str):
    """Retrieve results of a red team run."""
    if run_id not in _redteam_results:
        raise HTTPException(404, "Red team run not found")
    return _redteam_results[run_id]


# ── Guardrails Endpoints ─────────────────────────────────────────────

@ai_security_router.post("/guardrails", dependencies=[Depends(require_role(Role.ANALYST))])
async def check_guardrails(req: GuardrailRequest):
    """Evaluate content against runtime guardrails."""
    if req.direction == "input":
        verdict = _guardrails_engine.check_input(req.content)
    else:
        verdict = _guardrails_engine.check_output(req.content)

    # Telemetry
    _telemetry_engine.log(AIEvent(
        event_type=EventType.GUARDRAIL,
        source="guardrails_engine",
        severity="high" if not verdict.allowed else "info",
        data=verdict.to_dict(),
        risk_score=verdict.risk_score,
    ))

    return verdict.to_dict()


# ── Policy Endpoints ─────────────────────────────────────────────────

@ai_security_router.post("/policy/evaluate", dependencies=[Depends(require_role(Role.ANALYST))])
async def evaluate_policy(req: PolicyEvalRequest):
    """Evaluate an AI event against governance policies."""
    event = req.model_dump()
    assessment = _policy_engine.evaluate(event)

    # Telemetry
    _telemetry_engine.log(AIEvent(
        event_type=EventType.POLICY,
        source="policy_engine",
        severity=assessment.overall_severity.value,
        data=assessment.to_dict(),
        model=req.model,
        provider=req.provider,
        risk_score=assessment.overall_score,
    ))

    return assessment.to_dict()


@ai_security_router.get("/policy/rules", dependencies=[Depends(require_role(Role.ANALYST))])
async def list_policy_rules():
    """List all configured policy rules."""
    return {"rules": _policy_engine.list_rules()}


# ── Telemetry Endpoints ──────────────────────────────────────────────

@ai_security_router.get("/telemetry/stats", dependencies=[Depends(require_role(Role.ADMIN))])
async def telemetry_stats():
    """Get telemetry engine health and stats."""
    return _telemetry_engine.get_stats()


@ai_security_router.get("/telemetry/query", dependencies=[Depends(require_role(Role.ANALYST))])
async def telemetry_query(
    query_name: str = Query(..., description="Pre-built query name"),
):
    """Run a pre-built analytics query against ClickHouse."""
    from modules.telemetry.engine import ANALYTICS_QUERIES
    if query_name not in ANALYTICS_QUERIES:
        raise HTTPException(400, f"Unknown query. Available: {list(ANALYTICS_QUERIES.keys())}")
    results = _telemetry_engine.query(query_name)
    return {"query": query_name, "results": results}


# ── Connectors Endpoints ─────────────────────────────────────────────

@ai_security_router.get("/connectors", dependencies=[Depends(require_role(Role.ANALYST))])
async def list_connectors():
    """List registered LLM provider connectors."""
    return {"connectors": _connector_registry.list_providers()}


# ── Unified Dashboard ────────────────────────────────────────────────

@ai_security_router.get("/dashboard", dependencies=[Depends(require_role(Role.ANALYST))])
async def ai_dashboard():
    """
    Unified AI security dashboard summary.
    Aggregates status from all AI security modules.
    """
    return {
        "product": "AegisAI",
        "version": "3.0.0",
        "modules": {
            "connectors": {
                "status": "active",
                "providers": _connector_registry.list_providers(),
            },
            "discovery": {
                "status": "active",
                "last_scan": None,
            },
            "redteam": {
                "status": "active",
                "total_runs": len(_redteam_results),
            },
            "guardrails": {
                "status": "active",
                "mode": "redact" if _guardrails_engine.redact_mode else "block",
            },
            "policy": {
                "status": "active",
                "rule_count": len(_policy_engine.rules),
            },
            "telemetry": _telemetry_engine.get_stats(),
        },
        "nist_controls_covered": sorted(set([
            "CM-8", "PM-5", "RA-5",    # Discovery
            "CA-8", "SI-10", "AC-4",    # Red Team
            "SC-7", "AC-4", "SC-28",    # Guardrails
            "PL-1", "CA-2", "RA-3",    # Policy
            "AU-2", "AU-6", "AU-12",    # Telemetry
        ])),
        "compliance_frameworks": [
            "NIST 800-53 Rev5", "NIST AI RMF", "OWASP LLM Top 10",
            "MITRE ATLAS", "EU AI Act", "EO 14110", "ISO 42001",
        ],
    }
