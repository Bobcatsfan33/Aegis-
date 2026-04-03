"""
Tests for modules/tenants/middleware.py
Covers: TenantContext, TenantMiddleware, get_tenant_context(), get_tenant(),
        set_tenant_context(), _build_tenant_context(), JWT claim extraction.
All tests are self-contained; no external services required.
"""
from __future__ import annotations

import base64
import json
import pytest
from unittest.mock import AsyncMock, MagicMock

from modules.tenants.middleware import (
    TenantContext,
    TenantMiddleware,
    _build_tenant_context,
    _decode_jwt_payload,
    _extract_role_from_claims,
    _extract_tenant_from_claims,
    get_tenant,
    get_tenant_context,
    reset_tenant_context,
    set_tenant_context,
    tenant_context_dependency,
    _tenant_ctx_var,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_jwt(payload: dict) -> str:
    """Create a minimal unsigned JWT with the given payload."""
    header = base64.urlsafe_b64encode(b'{"alg":"none"}').rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{body}."


# ── TenantContext Tests ────────────────────────────────────────────────────────

class TestTenantContext:
    def test_default_values(self):
        ctx = TenantContext()
        assert ctx.tenant_id == "default"
        assert ctx.role == "analyst"
        assert ctx.owner_email is None

    def test_custom_values(self):
        ctx = TenantContext(tenant_id="org-123", role="admin", owner_email="a@b.com")
        assert ctx.tenant_id == "org-123"
        assert ctx.role == "admin"
        assert ctx.owner_email == "a@b.com"

    def test_get_method_returns_attr(self):
        ctx = TenantContext(tenant_id="x")
        assert ctx.get("tenant_id") == "x"

    def test_get_method_default(self):
        ctx = TenantContext()
        assert ctx.get("nonexistent", "fallback") == "fallback"

    def test_to_dict(self):
        ctx = TenantContext(tenant_id="t1", role="owner", owner_email="e@e.com")
        d = ctx.to_dict()
        assert d["tenant_id"] == "t1"
        assert d["role"] == "owner"
        assert d["owner_email"] == "e@e.com"

    def test_claims_field_default_empty(self):
        ctx = TenantContext()
        assert ctx.claims == {}


# ── JWT Helpers Tests ─────────────────────────────────────────────────────────

class TestJWTHelpers:
    def test_decode_valid_jwt(self):
        payload = {"sub": "user1", "tenant_id": "org-abc", "role": "admin"}
        token = _make_jwt(payload)
        claims = _decode_jwt_payload(token)
        assert claims["tenant_id"] == "org-abc"
        assert claims["role"] == "admin"

    def test_decode_malformed_jwt_returns_empty(self):
        claims = _decode_jwt_payload("not.a.jwt.at.all.extra")
        assert claims == {}

    def test_decode_empty_string_returns_empty(self):
        assert _decode_jwt_payload("") == {}

    def test_decode_one_segment_returns_empty(self):
        assert _decode_jwt_payload("onlyone") == {}

    def test_extract_tenant_from_explicit_claim(self):
        claims = {"tenant_id": "org-xyz"}
        assert _extract_tenant_from_claims(claims) == "org-xyz"

    def test_extract_tenant_from_sub_slash(self):
        claims = {"sub": "orgABC/user42"}
        assert _extract_tenant_from_claims(claims) == "orgABC"

    def test_extract_tenant_default_fallback(self):
        assert _extract_tenant_from_claims({}) == "default"

    def test_extract_role_string(self):
        assert _extract_role_from_claims({"role": "owner"}) == "owner"

    def test_extract_role_list_picks_highest(self):
        role = _extract_role_from_claims({"role": ["readonly", "admin", "analyst"]})
        assert role == "admin"

    def test_extract_role_default_fallback(self):
        assert _extract_role_from_claims({}) == "analyst"


# ── _build_tenant_context Tests ───────────────────────────────────────────────

class TestBuildTenantContext:
    def test_header_tenant_wins_over_jwt(self):
        token = _make_jwt({"tenant_id": "from-jwt"})
        ctx = _build_tenant_context(
            tenant_id_header="from-header",
            authorization=f"Bearer {token}",
        )
        assert ctx.tenant_id == "from-header"

    def test_jwt_tenant_used_when_no_header(self):
        token = _make_jwt({"tenant_id": "jwt-tenant", "role": "admin"})
        ctx = _build_tenant_context(authorization=f"Bearer {token}")
        assert ctx.tenant_id == "jwt-tenant"

    def test_default_tenant_when_no_header_no_jwt(self):
        ctx = _build_tenant_context()
        assert ctx.tenant_id == "default"

    def test_role_header_wins_over_jwt(self):
        token = _make_jwt({"role": "readonly"})
        ctx = _build_tenant_context(
            role_header="owner",
            authorization=f"Bearer {token}",
        )
        assert ctx.role == "owner"

    def test_invalid_role_falls_back_to_analyst(self):
        ctx = _build_tenant_context(role_header="superuser")
        assert ctx.role == "analyst"

    def test_claims_populated(self):
        token = _make_jwt({"sub": "u1", "tenant_id": "t1", "role": "admin"})
        ctx = _build_tenant_context(authorization=f"Bearer {token}")
        assert ctx.claims.get("sub") == "u1"

    def test_bearer_case_insensitive(self):
        token = _make_jwt({"tenant_id": "ci-tenant"})
        ctx = _build_tenant_context(authorization=f"bearer {token}")
        assert ctx.tenant_id == "ci-tenant"


# ── Context Var Tests ─────────────────────────────────────────────────────────

class TestContextVar:
    def test_get_tenant_context_default_when_none(self):
        # Reset to None explicitly
        token = _tenant_ctx_var.set(None)  # type: ignore[arg-type]
        try:
            ctx = get_tenant_context()
            assert ctx.tenant_id == "default"
        finally:
            _tenant_ctx_var.reset(token)

    def test_set_and_get_tenant_context(self):
        custom = TenantContext(tenant_id="test-tenant", role="owner")
        token = set_tenant_context(custom)
        try:
            ctx = get_tenant_context()
            assert ctx.tenant_id == "test-tenant"
            assert ctx.role == "owner"
        finally:
            reset_tenant_context(token)

    def test_get_tenant_alias(self):
        custom = TenantContext(tenant_id="alias-test")
        token = set_tenant_context(custom)
        try:
            assert get_tenant().tenant_id == "alias-test"
        finally:
            reset_tenant_context(token)

    def test_tenant_context_dependency(self):
        custom = TenantContext(tenant_id="dep-test")
        token = set_tenant_context(custom)
        try:
            result = tenant_context_dependency()
            assert result.tenant_id == "dep-test"
        finally:
            reset_tenant_context(token)

    def test_context_isolation_after_reset(self):
        custom = TenantContext(tenant_id="isolated")
        token = set_tenant_context(custom)
        reset_tenant_context(token)
        # After reset, get_tenant_context should return default
        ctx = get_tenant_context()
        assert ctx.tenant_id == "default"


# ── TenantMiddleware Tests ────────────────────────────────────────────────────

def _make_scope(headers: dict | None = None) -> dict:
    raw_headers = []
    if headers:
        for k, v in headers.items():
            raw_headers.append((k.lower().encode(), v.encode()))
    return {"type": "http", "headers": raw_headers}


def _run_middleware_sync(scope: dict, app_fn=None, mw_kwargs=None) -> TenantContext:
    """Run middleware synchronously via asyncio.run and return captured context."""
    import asyncio
    captured: list[TenantContext] = []

    async def default_app(s, r, send):
        captured.append(get_tenant_context())

    the_app = app_fn or default_app

    async def _run():
        kwargs = mw_kwargs or {}
        mw = TenantMiddleware(the_app, **kwargs)
        receive = AsyncMock()
        send = AsyncMock()
        await mw(scope, receive, send)

    asyncio.run(_run())
    return captured[0] if captured else get_tenant_context()


class TestTenantMiddleware:
    """Test the ASGI middleware by constructing minimal ASGI scopes."""

    def test_sets_default_context(self):
        ctx = _run_middleware_sync(_make_scope())
        assert ctx.tenant_id == "default"

    def test_extracts_tenant_from_header(self):
        ctx = _run_middleware_sync(_make_scope({"x-tenant-id": "org-99"}))
        assert ctx.tenant_id == "org-99"

    def test_extracts_role_from_header(self):
        ctx = _run_middleware_sync(_make_scope({"x-tenant-role": "owner"}))
        assert ctx.role == "owner"

    def test_extracts_tenant_from_jwt(self):
        token = _make_jwt({"tenant_id": "jwt-org", "role": "admin"})
        ctx = _run_middleware_sync(_make_scope({"authorization": f"Bearer {token}"}))
        assert ctx.tenant_id == "jwt-org"

    def test_passthrough_for_non_http_scope(self):
        """Lifespan / websocket non-http scopes should not crash."""
        import asyncio
        called: list[bool] = []

        async def app(s, r, send):
            called.append(True)

        async def _run():
            mw = TenantMiddleware(app)
            scope = {"type": "lifespan"}
            await mw(scope, AsyncMock(), AsyncMock())

        asyncio.run(_run())
        assert called

    def test_context_reset_after_request(self):
        """Context must be reset to its pre-request state after the request ends."""
        _run_middleware_sync(_make_scope({"x-tenant-id": "ephemeral"}))
        # After middleware call, context should be gone (back to default)
        ctx = get_tenant_context()
        assert ctx.tenant_id == "default"

    def test_custom_default_tenant_id(self):
        """When no header or JWT, custom default should be used."""
        import asyncio
        called: list[TenantContext] = []

        async def app(s, r, send):
            called.append(get_tenant_context())

        async def _run():
            mw = TenantMiddleware(app, default_tenant_id="fallback-org")
            scope = _make_scope()
            await mw(scope, AsyncMock(), AsyncMock())

        asyncio.run(_run())
        assert called[0].tenant_id == "fallback-org"
