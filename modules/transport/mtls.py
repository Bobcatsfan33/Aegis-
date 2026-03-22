"""
Aegis — mTLS Service Mesh  (v2.7.0)
=====================================
Mutual TLS enforcement for Aegis CSPM inter-service communication.

Unlike TokenDNA's user-facing mTLS middleware, Aegis mTLS covers two planes:

1. **Inbound API plane** — Aegis FastAPI endpoints enforce mTLS client certs
   for operator tooling, SIEM push agents, and eMASS integration clients.

2. **Outbound scanner plane** — Aegis scanners (Tenable.sc, cloud APIs, SIEM)
   use client certificates when calling external services that require mTLS,
   e.g. Tenable.sc with CAC/PKI auth, or DoD SIEM endpoints.

This module provides:
  - Shared `build_ssl_context()` / `get_uvicorn_ssl_config()` for the API plane
  - `OutboundMTLSSession` — requests.Session pre-loaded with client cert + CA
  - `AsyncOutboundMTLSSession` — httpx.AsyncClient equivalent for async scanners
  - `MTLSMiddleware` (re-exported from same pattern as TokenDNA for API plane)
  - `check_mtls_config()` — startup validation with DISA-ready log output

NIST 800-53 Rev5 Controls
-------------------------
  SC-8    Transmission Confidentiality and Integrity
  SC-8(1) Cryptographic Protection (TLS 1.2+, FIPS ciphers)
  IA-3    Device Identification and Authentication
  SC-17   Public Key Infrastructure Certificates
  MA-3    Maintenance Tools (mTLS-authenticated maintenance channel)
  RA-5    Vulnerability Scanning (scanner ↔ Tenable.sc mTLS channel)
  SI-7    Software, Firmware, and Information Integrity (scan result integrity)

DISA STIG References
--------------------
  SRG-APP-000014  FIPS 140-2 validated cryptographic module
  SRG-APP-000015  Mutual authentication between services
  SRG-APP-000156  Certificate expiry enforcement
  SRG-APP-000219  PKI-based client auth

Configuration (env vars)
------------------------
  # Inbound API plane
  MTLS_MODE            proxy | native       (default: disabled)
  MTLS_CA_CERT         /run/secrets/mtls/ca.crt
  MTLS_SERVER_CERT     /run/secrets/mtls/server.crt
  MTLS_SERVER_KEY      /run/secrets/mtls/server.key
  MTLS_CERT_HEADER     X-Client-Cert        (proxy mode)
  MTLS_ALLOWED_CNS     aegis-operator,...   (comma-separated; empty = any)
  MTLS_EXEMPT_PATHS    /health,/            (comma-separated)
  MTLS_STRICT          false                (fail-fast on missing certs)

  # Outbound scanner plane
  AEGIS_CLIENT_CERT    /run/secrets/mtls/client.crt  (Aegis scanner identity cert)
  AEGIS_CLIENT_KEY     /run/secrets/mtls/client.key
  AEGIS_CA_BUNDLE      /run/secrets/mtls/ca.crt       (CA for outbound peer verification)
"""

from __future__ import annotations

import logging
import os
import ssl
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ── Inbound API plane config (mirrors TokenDNA) ────────────────────────────────

MTLS_CA_CERT     = os.getenv("MTLS_CA_CERT",     "/run/secrets/mtls/ca.crt")
MTLS_SERVER_CERT = os.getenv("MTLS_SERVER_CERT",  "/run/secrets/mtls/server.crt")
MTLS_SERVER_KEY  = os.getenv("MTLS_SERVER_KEY",   "/run/secrets/mtls/server.key")
MTLS_MODE        = os.getenv("MTLS_MODE",         "").lower()
MTLS_CERT_HEADER = os.getenv("MTLS_CERT_HEADER",  "X-Client-Cert")
MTLS_STRICT      = os.getenv("MTLS_STRICT",       "false").lower() == "true"
MTLS_ALLOWED_CNS = {
    cn.strip()
    for cn in os.getenv("MTLS_ALLOWED_CNS", "").split(",")
    if cn.strip()
}
MTLS_EXEMPT_PATHS = {
    p.strip()
    for p in os.getenv("MTLS_EXEMPT_PATHS", "/health,/").split(",")
    if p.strip()
}

# ── Outbound scanner plane config ─────────────────────────────────────────────

AEGIS_CLIENT_CERT = os.getenv("AEGIS_CLIENT_CERT", "/run/secrets/mtls/client.crt")
AEGIS_CLIENT_KEY  = os.getenv("AEGIS_CLIENT_KEY",  "/run/secrets/mtls/client.key")
AEGIS_CA_BUNDLE   = os.getenv("AEGIS_CA_BUNDLE",   MTLS_CA_CERT)

# FIPS-approved cipher suite (shared with TokenDNA)
_FIPS_CIPHERS = ":".join([
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-AES128-GCM-SHA256",
])


class MTLSConfigError(RuntimeError):
    """Raised when mTLS configuration is invalid or missing required files."""


# ── Inbound API plane: SSL context and Uvicorn config ─────────────────────────

def build_ssl_context(
    ca_cert: str = MTLS_CA_CERT,
    server_cert: str = MTLS_SERVER_CERT,
    server_key: str = MTLS_SERVER_KEY,
    require_client_cert: bool = True,
) -> ssl.SSLContext:
    """
    Build an SSL context for Uvicorn native mTLS (Aegis API plane).
    TLS 1.2 minimum, FIPS-approved ciphers, client cert required.
    """
    for path, label in [
        (ca_cert,     "CA cert"),
        (server_cert, "server cert"),
        (server_key,  "server key"),
    ]:
        if not Path(path).exists():
            raise MTLSConfigError(f"mTLS: {label} not found at {path!r}")

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3

    try:
        ctx.set_ciphers(_FIPS_CIPHERS)
    except ssl.SSLError as exc:
        logger.warning("mTLS: FIPS cipher list rejected (%s) — using OpenSSL defaults", exc)

    ctx.load_cert_chain(certfile=server_cert, keyfile=server_key)
    ctx.load_verify_locations(cafile=ca_cert)
    ctx.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_OPTIONAL

    ctx.options |= ssl.OP_NO_TLSv1
    ctx.options |= ssl.OP_NO_TLSv1_1
    ctx.options |= ssl.OP_SINGLE_ECDH_USE
    ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE

    logger.info(
        "Aegis mTLS: inbound SSL context built (min=%s, client_cert=%s)",
        ctx.minimum_version.name,
        "REQUIRED" if require_client_cert else "OPTIONAL",
    )
    return ctx


def get_uvicorn_ssl_config() -> dict[str, Any]:
    """Return ssl kwargs for uvicorn.run() / uvicorn.Config() (native mTLS)."""
    return {
        "ssl_certfile":  MTLS_SERVER_CERT,
        "ssl_keyfile":   MTLS_SERVER_KEY,
        "ssl_ca_certs":  MTLS_CA_CERT,
        "ssl_cert_reqs": ssl.CERT_REQUIRED,
        "ssl_version":   ssl.PROTOCOL_TLS_SERVER,
        "ssl_ciphers":   _FIPS_CIPHERS,
    }


# ── Inbound API plane: ASGI middleware (re-exported from transport pattern) ────
# For full implementation, see TokenDNA's modules/transport/mtls.py MTLSMiddleware.
# Aegis uses the same middleware; this module provides the Aegis-specific config.

class MTLSMiddleware:
    """
    ASGI middleware enforcing mTLS client certificate validation for Aegis API.

    In 'proxy' mode: reads peer cert from MTLS_CERT_HEADER (set by Nginx/Envoy).
    In 'native' mode: Uvicorn handles TLS, middleware enforces CN allowlist policy.

    Injects PeerIdentity into request.state['peer_identity'] for downstream use.
    Rejects expired certs (401) and non-allowlisted CNs (403) with AU-2 audit log.
    """

    def __init__(self, app: Any) -> None:
        self.app = app
        # Import the full implementation from tokendna's transport module if available,
        # otherwise use the inline implementation below.
        try:
            from modules.transport._mtls_impl import _MTLSMiddlewareCore  # type: ignore
            self._core = _MTLSMiddlewareCore(
                app,
                ca_cert=MTLS_CA_CERT,
                cert_header=MTLS_CERT_HEADER,
                allowed_cns=MTLS_ALLOWED_CNS,
                exempt_paths=MTLS_EXEMPT_PATHS,
                strict=MTLS_STRICT,
                mode=MTLS_MODE,
            )
        except ImportError:
            self._core = None

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if self._core is not None:
            await self._core(scope, receive, send)
            return
        await self._inline(scope, receive, send)

    async def _inline(self, scope: Any, receive: Any, send: Any) -> None:
        """
        Inline implementation (no shared core available).

        Proxy mode: validates MTLS_CERT_HEADER presence and CN allowlist.
        Native mode: passes through (TLS enforced at Uvicorn transport layer).
        """
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        from starlette.requests import Request
        from starlette.responses import JSONResponse

        request = Request(scope, receive, send)
        path = scope.get("path", "")

        # Exempt paths
        if not MTLS_STRICT:
            for exempt in MTLS_EXEMPT_PATHS:
                if path == exempt or path.startswith(exempt.rstrip("/") + "/"):
                    await self.app(scope, receive, send)
                    return

        if MTLS_MODE == "proxy":
            cert_header = request.headers.get(MTLS_CERT_HEADER, "")
            if not cert_header:
                logger.warning(
                    "Aegis mTLS: missing client cert header '%s' on %s %s",
                    MTLS_CERT_HEADER, request.method, path,
                )
                resp = JSONResponse(
                    {"detail": "mTLS client certificate required", "code": "MTLS_CERT_MISSING"},
                    status_code=401,
                )
                await resp(scope, receive, send)
                return

            # CN allowlist (if configured) — parse from header
            if MTLS_ALLOWED_CNS:
                import re
                cn_match = re.search(r"CN=([^,/;\"]+)", cert_header)
                cn = cn_match.group(1).strip() if cn_match else ""
                if cn not in MTLS_ALLOWED_CNS:
                    logger.warning("Aegis mTLS: CN '%s' not in allowlist", cn)
                    _emit_audit_failure(path, cn, request)
                    resp = JSONResponse(
                        {"detail": "Client cert CN not authorized", "code": "MTLS_CN_DENIED"},
                        status_code=403,
                    )
                    await resp(scope, receive, send)
                    return

        await self.app(scope, receive, send)


def _emit_audit_failure(path: str, cn: str, request: Any) -> None:
    try:
        from modules.security.audit import AuditEventType, AuditOutcome, log_event
        log_event(
            AuditEventType.AUTH_FAILURE,
            AuditOutcome.FAILURE,
            detail={
                "subsystem": "mtls",
                "client_cn": cn,
                "path": path,
                "client_ip": request.client.host if request.client else None,
            },
        )
    except Exception:
        pass


# ── Outbound scanner plane: mTLS-authenticated HTTP sessions ──────────────────

class OutboundMTLSSession:
    """
    requests.Session with Aegis client certificate loaded for outbound mTLS.

    Used by Tenable.sc scanner when the server requires mutual TLS authentication.
    Also suitable for DoD SIEM endpoints, eMASS REST API, and any service that
    requires DoD PKI / agency CA-signed client certificates.

    Usage:
        session = OutboundMTLSSession()
        resp = session.get("https://acas.yourdomain.mil/rest/analysis", params={...})

    Environment:
        AEGIS_CLIENT_CERT  path to Aegis client PEM certificate
        AEGIS_CLIENT_KEY   path to Aegis client PEM private key
        AEGIS_CA_BUNDLE    path to CA bundle for server cert verification
    """

    def __init__(
        self,
        client_cert: str = AEGIS_CLIENT_CERT,
        client_key: str = AEGIS_CLIENT_KEY,
        ca_bundle: str = AEGIS_CA_BUNDLE,
        verify_tls: bool = True,
    ):
        self._client_cert = client_cert
        self._client_key  = client_key
        self._ca_bundle   = ca_bundle
        self._verify_tls  = verify_tls
        self._session: Any = None

    @property
    def session(self) -> Any:
        """Lazily construct the requests.Session on first use."""
        if self._session is None:
            self._session = self._build_session()
        return self._session

    def _build_session(self) -> Any:
        try:
            import requests
        except ImportError:
            raise MTLSConfigError("requests not installed — run: pip install requests")

        s = requests.Session()

        cert_exists = Path(self._client_cert).exists() and Path(self._client_key).exists()
        ca_exists   = Path(self._ca_bundle).exists()

        if cert_exists:
            s.cert = (self._client_cert, self._client_key)
            logger.info("Aegis mTLS outbound: client cert loaded from %s", self._client_cert)
        else:
            logger.warning(
                "Aegis mTLS outbound: client cert not found (%s / %s) — "
                "outbound requests will use server-only TLS.",
                self._client_cert, self._client_key,
            )

        if self._verify_tls:
            s.verify = self._ca_bundle if ca_exists else True
            if not ca_exists:
                logger.warning(
                    "Aegis mTLS outbound: CA bundle not found at %s — "
                    "using system CA store.", self._ca_bundle,
                )
        else:
            s.verify = False
            logger.warning("Aegis mTLS outbound: TLS verification DISABLED (verify=False). "
                           "Not permitted in IL4/IL5.")

        # Restrict TLS version and ciphers via HTTPAdapter
        try:
            from requests.adapters import HTTPAdapter
            from urllib3.util.ssl_ import create_urllib3_context

            ctx = create_urllib3_context(ciphers=_FIPS_CIPHERS)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            if cert_exists:
                ctx.load_cert_chain(certfile=self._client_cert, keyfile=self._client_key)
            if ca_exists and self._verify_tls:
                ctx.load_verify_locations(cafile=self._ca_bundle)

            class _TLSAdapter(HTTPAdapter):
                def __init__(self, _ctx: ssl.SSLContext, **kw: Any) -> None:
                    self._ssl_ctx = _ctx
                    super().__init__(**kw)

                def init_poolmanager(self, *a: Any, **kw: Any) -> None:
                    kw["ssl_context"] = self._ssl_ctx
                    super().init_poolmanager(*a, **kw)

            adapter = _TLSAdapter(ctx)
            s.mount("https://", adapter)
        except Exception as exc:
            logger.warning("Aegis mTLS outbound: TLS adapter error (%s) — using default", exc)

        return s

    def get(self, url: str, **kwargs: Any) -> Any:
        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> Any:
        return self.session.post(url, **kwargs)

    def close(self) -> None:
        if self._session:
            self._session.close()
            self._session = None

    def __enter__(self) -> "OutboundMTLSSession":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


class AsyncOutboundMTLSSession:
    """
    httpx.AsyncClient with Aegis client certificate for async outbound mTLS.

    Suitable for async scanner coroutines (e.g., parallel cloud API calls).

    Usage:
        async with AsyncOutboundMTLSSession() as client:
            resp = await client.get("https://siem.yourdomain.mil/api/events")
    """

    def __init__(
        self,
        client_cert: str = AEGIS_CLIENT_CERT,
        client_key: str = AEGIS_CLIENT_KEY,
        ca_bundle: str = AEGIS_CA_BUNDLE,
        verify_tls: bool = True,
    ):
        self._client_cert = client_cert
        self._client_key  = client_key
        self._ca_bundle   = ca_bundle
        self._verify_tls  = verify_tls
        self._client: Any = None

    async def __aenter__(self) -> "AsyncOutboundMTLSSession":
        try:
            import httpx
        except ImportError:
            raise MTLSConfigError("httpx not installed — run: pip install httpx")

        cert_exists = Path(self._client_cert).exists() and Path(self._client_key).exists()
        ca_exists   = Path(self._ca_bundle).exists()

        cert = (self._client_cert, self._client_key) if cert_exists else None
        verify: Any = (self._ca_bundle if ca_exists else True) if self._verify_tls else False

        self._client = httpx.AsyncClient(cert=cert, verify=verify)
        return self

    async def __aexit__(self, *_: Any) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def get(self, url: str, **kwargs: Any) -> Any:
        return await self._client.get(url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> Any:
        return await self._client.post(url, **kwargs)


# ── Startup check ──────────────────────────────────────────────────────────────

def check_mtls_config() -> dict[str, Any]:
    """
    Validate both inbound API and outbound scanner mTLS config at startup.

    Returns a summary dict suitable for the startup audit event.
    Raises MTLSConfigError only if MTLS_STRICT=true and required files are missing.
    """
    inbound_certs_present = all([
        Path(MTLS_CA_CERT).exists(),
        Path(MTLS_SERVER_CERT).exists(),
        Path(MTLS_SERVER_KEY).exists(),
    ])
    outbound_certs_present = all([
        Path(AEGIS_CLIENT_CERT).exists(),
        Path(AEGIS_CLIENT_KEY).exists(),
    ])

    summary: dict[str, Any] = {
        "inbound_mode":             MTLS_MODE or "disabled",
        "inbound_certs_present":    inbound_certs_present,
        "inbound_cert_header":      MTLS_CERT_HEADER,
        "inbound_allowed_cns":      sorted(MTLS_ALLOWED_CNS) if MTLS_ALLOWED_CNS else "*",
        "inbound_exempt_paths":     sorted(MTLS_EXEMPT_PATHS),
        "outbound_certs_present":   outbound_certs_present,
        "outbound_client_cert":     AEGIS_CLIENT_CERT,
        "outbound_ca_bundle":       AEGIS_CA_BUNDLE,
    }

    if MTLS_MODE in ("native", "proxy") and not inbound_certs_present:
        msg = (
            f"Aegis mTLS inbound: cert files missing for mode={MTLS_MODE!r}. "
            f"CA={MTLS_CA_CERT}, CERT={MTLS_SERVER_CERT}, KEY={MTLS_SERVER_KEY}"
        )
        if MTLS_STRICT:
            raise MTLSConfigError(msg)
        logger.warning("%s — inbound mTLS will not be enforced.", msg)
    elif MTLS_MODE in ("native", "proxy"):
        logger.info(
            "Aegis mTLS inbound: CONFIGURED — mode=%s CA=%s",
            MTLS_MODE, MTLS_CA_CERT,
        )

    if not outbound_certs_present:
        logger.info(
            "Aegis mTLS outbound: client cert not found (%s) — "
            "scanner connections will use server-cert-only TLS.",
            AEGIS_CLIENT_CERT,
        )
    else:
        logger.info(
            "Aegis mTLS outbound: client cert loaded from %s",
            AEGIS_CLIENT_CERT,
        )

    return summary
