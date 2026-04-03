"""
Aegis — Multi-Tenant Context Middleware  (v3.1.0)
==================================================
FedRAMP High / IL6: NIST 800-53 Rev5 AC-2, AC-3, AC-4, SC-28

Provides per-request tenant isolation via:
  • TenantMiddleware — Starlette/FastAPI ASGI middleware
  • get_tenant_context() / get_tenant() — dependency-injection helpers

Tenant ID is resolved (in order of precedence):
  1. ``X-Tenant-ID`` request header
  2. ``tenant_id`` claim in the Bearer JWT payload
  3. ``sub`` prefix split on ``/`` (e.g. ``orgXYZ/user1`` → tenant ``orgXYZ``)
  4. Fallback → ``"default"``

Role is resolved from:
  1. ``role`` JWT claim (lowercased)
  2. ``X-Tenant-Role`` header (for service-mesh / M2M contexts)
  3. Fallback → ``"analyst"``

Context is stored in a ``contextvars.ContextVar`` so it is coroutine-safe and
does not leak across concurrent requests.

Usage (FastAPI)::

    from modules.tenants.middleware import TenantMiddleware, get_tenant_context

    app.add_middleware(TenantMiddleware)

    @app.get("/protected")
    async def handler():
        ctx = get_tenant_context()
        print(ctx.tenant_id, ctx.role)
"""

from __future__ import annotations

import base64
import json
import logging
import re
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger("aegis.tenants")

# ── Per-request context storage ───────────────────────────────────────────────
_tenant_ctx_var: ContextVar["TenantContext"] = ContextVar(
    "_aegis_tenant_ctx",
    default=None,   # type: ignore[arg-type]
)


# ── Domain model ──────────────────────────────────────────────────────────────
@dataclass
class TenantContext:
    """
    Immutable tenant context attached to each request.

    Attributes:
        tenant_id    — Unique tenant identifier (e.g. ``"org-123"``).
        role         — String role name: ``"owner"`` / ``"admin"`` /
                       ``"analyst"`` / ``"readonly"``
        owner_email  — Optional e-mail address of the tenant owner.
        claims       — Full decoded JWT claims dict (if a token was present).
    """
    tenant_id: str = "default"
    role: str = "analyst"
    owner_email: Optional[str] = None
    claims: Dict[str, Any] = field(default_factory=dict)

    # dict-like access so existing code using `.get("sub", ...)` keeps working
    def get(self, key: str, default: Any = None) -> Any:  # noqa: D401
        return getattr(self, key, default)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id":   self.tenant_id,
            "role":        self.role,
            "owner_email": self.owner_email,
        }


# ── JWT helpers ───────────────────────────────────────────────────────────────
_BEARER_RE = re.compile(r"^Bearer\s+(.+)$", re.IGNORECASE)


def _decode_jwt_payload(token: str) -> Dict[str, Any]:
    """
    Decode JWT payload without signature verification.

    Signature verification is performed upstream (``auth.py`` / API gateway).
    Here we only need the claims for tenant routing.

    Returns an empty dict if the token is malformed.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return {}
        # Add padding so base64 decoding succeeds
        payload_b64 = parts[1]
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        data = base64.urlsafe_b64decode(payload_b64)
        return json.loads(data)
    except Exception:
        return {}


def _extract_tenant_from_claims(claims: Dict[str, Any]) -> str:
    """Derive tenant_id from JWT claims."""
    # Explicit tenant_id claim wins
    if "tenant_id" in claims:
        return str(claims["tenant_id"])
    # sub can be "orgXYZ/user1" format
    sub = claims.get("sub", "")
    if "/" in sub:
        return sub.split("/", 1)[0]
    return "default"


def _extract_role_from_claims(claims: Dict[str, Any]) -> str:
    """Derive role string from JWT claims."""
    role = claims.get("role", "") or claims.get("roles", "")
    if isinstance(role, list):
        # pick highest role if multiple are present
        order = {"owner": 4, "admin": 3, "analyst": 2, "readonly": 1}
        role = max(role, key=lambda r: order.get(r.lower(), 0), default="analyst")
    return str(role).lower() if role else "analyst"


# ── Context builder ───────────────────────────────────────────────────────────
def _build_tenant_context(
    tenant_id_header: Optional[str] = None,
    role_header: Optional[str] = None,
    authorization: Optional[str] = None,
) -> TenantContext:
    """
    Build a TenantContext from HTTP request headers.

    Priority order:
      1. X-Tenant-ID header (overrides JWT)
      2. JWT claims
      3. Defaults
    """
    claims: Dict[str, Any] = {}

    # Try to decode JWT
    if authorization:
        m = _BEARER_RE.match(authorization)
        if m:
            claims = _decode_jwt_payload(m.group(1))

    # Tenant ID resolution
    if tenant_id_header:
        tenant_id = tenant_id_header.strip()
    else:
        tenant_id = _extract_tenant_from_claims(claims) if claims else "default"

    # Role resolution
    if role_header:
        role = role_header.strip().lower()
    else:
        role = _extract_role_from_claims(claims) if claims else "analyst"

    # Valid roles only
    valid_roles = {"owner", "admin", "analyst", "readonly"}
    if role not in valid_roles:
        role = "analyst"

    owner_email = claims.get("email") or claims.get("sub") or None

    return TenantContext(
        tenant_id=tenant_id,
        role=role,
        owner_email=owner_email,
        claims=claims,
    )


# ── ASGI Middleware ────────────────────────────────────────────────────────────
class TenantMiddleware:
    """
    Starlette / FastAPI ASGI middleware for per-request tenant isolation.

    Extracts tenant context from incoming headers / JWT and stores it in a
    ``ContextVar`` so any downstream code can retrieve it via
    ``get_tenant_context()`` without threading through parameters.

    Configuration::

        app.add_middleware(TenantMiddleware)

    Optional keyword arguments:
        default_tenant_id   — Fallback tenant when none is found (default ``"default"``).
        default_role        — Fallback role when none is found (default ``"analyst"``).
        tenant_header       — Header name for explicit tenant override (default ``"X-Tenant-ID"``).
        role_header         — Header name for M2M role injection (default ``"X-Tenant-Role"``).
    """

    def __init__(
        self,
        app: Callable,
        default_tenant_id: str = "default",
        default_role: str = "analyst",
        tenant_header: str = "X-Tenant-ID",
        role_header: str = "X-Tenant-Role",
    ) -> None:
        self.app = app
        self.default_tenant_id = default_tenant_id
        self.default_role = default_role
        self.tenant_header = tenant_header.lower()
        self.role_header = role_header.lower()

    async def __call__(self, scope: dict, receive: Callable, send: Callable) -> None:
        if scope["type"] in ("http", "websocket"):
            headers = dict(scope.get("headers", []))

            # ASGI headers are bytes
            def _h(name: str) -> Optional[str]:
                val = headers.get(name.encode(), headers.get(name.lower().encode()))
                return val.decode() if val else None

            ctx = _build_tenant_context(
                tenant_id_header=_h(self.tenant_header),
                role_header=_h(self.role_header),
                authorization=_h("authorization"),
            )
            # Use defaults if nothing was resolved
            if ctx.tenant_id == "default" and self.default_tenant_id != "default":
                ctx = TenantContext(
                    tenant_id=self.default_tenant_id,
                    role=ctx.role,
                    owner_email=ctx.owner_email,
                    claims=ctx.claims,
                )

            token = _tenant_ctx_var.set(ctx)
            try:
                await self.app(scope, receive, send)
            finally:
                _tenant_ctx_var.reset(token)
        else:
            await self.app(scope, receive, send)


# ── Public API ─────────────────────────────────────────────────────────────────
def get_tenant_context() -> TenantContext:
    """
    Return the TenantContext for the current request.

    Returns a default ``TenantContext`` when called outside of a request
    context (e.g. background tasks, tests) so callers never receive ``None``.

    Usage in FastAPI route::

        from modules.tenants.middleware import get_tenant_context

        @app.get("/resource")
        async def handler():
            ctx = get_tenant_context()
            return {"tenant_id": ctx.tenant_id}
    """
    ctx = _tenant_ctx_var.get(None)
    if ctx is None:
        return TenantContext()
    return ctx


def get_tenant() -> TenantContext:
    """
    Alias for ``get_tenant_context()``.

    Kept for backward compatibility with ``modules.security.rbac`` which calls
    ``get_tenant()``.
    """
    return get_tenant_context()


def set_tenant_context(ctx: TenantContext) -> Any:
    """
    Manually set the tenant context (useful in tests / background tasks).

    Returns the ``ContextVar`` token so callers can reset it::

        token = set_tenant_context(TenantContext(tenant_id="test-org", role="admin"))
        try:
            ...
        finally:
            _tenant_ctx_var.reset(token)
    """
    return _tenant_ctx_var.set(ctx)


def reset_tenant_context(token: Any) -> None:
    """Reset the tenant context to its previous value (cleanup after set_tenant_context)."""
    _tenant_ctx_var.reset(token)


# ── FastAPI Dependency ────────────────────────────────────────────────────────
def tenant_context_dependency() -> TenantContext:
    """
    FastAPI ``Depends()`` helper that returns the current tenant context.

    Usage::

        @app.get("/resource")
        async def handler(tenant: TenantContext = Depends(tenant_context_dependency)):
            return {"tenant_id": tenant.tenant_id}
    """
    return get_tenant_context()
