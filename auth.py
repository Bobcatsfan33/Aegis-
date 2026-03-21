"""
JWT / OIDC authentication for the Aegis API.

Fixes vs. original:
  - OIDC_ISSUER / AUDIENCE loaded from config (not hardcoded placeholders).
  - JWKS is fetched lazily and cached; a single cache-miss refresh is attempted
    when no matching key is found (handles key rotation without server restart).
  - next() uses a default of None + explicit 401 instead of raising StopIteration.
  - Descriptive error messages in logs (token detail never leaked to the client).
"""

import logging
import threading
from typing import Optional

import requests
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from config import DEV_MODE, OIDC_AUDIENCE, OIDC_ISSUER

logger = logging.getLogger(__name__)
security = HTTPBearer(auto_error=not DEV_MODE)

# ── JWKS cache ────────────────────────────────────────────────────────────────

_jwks_cache: Optional[dict] = None
_jwks_lock = threading.Lock()


def _jwks_url() -> str:
    return f"{OIDC_ISSUER}/.well-known/jwks.json"


def _fetch_jwks(force_refresh: bool = False) -> dict:
    global _jwks_cache
    with _jwks_lock:
        if _jwks_cache is None or force_refresh:
            if not OIDC_ISSUER:
                raise RuntimeError(
                    "OIDC_ISSUER is not configured. Set it in your .env file."
                )
            try:
                resp = requests.get(_jwks_url(), timeout=10)
                resp.raise_for_status()
                _jwks_cache = resp.json()
                logger.info("JWKS refreshed successfully.")
            except Exception as e:
                logger.error(f"Failed to fetch JWKS from {_jwks_url()}: {e}")
                if _jwks_cache is None:
                    raise
        return _jwks_cache


def _find_key(kid: str, allow_refresh: bool = True) -> Optional[dict]:
    """Look up a signing key by kid, refreshing the cache once on miss."""
    jwks = _fetch_jwks()
    key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    if key is None and allow_refresh:
        logger.info(f"Key '{kid}' not found in cache — refreshing JWKS.")
        jwks = _fetch_jwks(force_refresh=True)
        key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
    return key


# ── Token verification ────────────────────────────────────────────────────────

def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    """
    FastAPI dependency. Validates a Bearer JWT and returns the decoded payload.
    Raises HTTP 401 on any failure.

    When DEV_MODE=true the token is not verified — a synthetic payload is returned
    so you can call the API locally without a real OIDC provider.
    """
    if DEV_MODE:
        logger.warning("DEV_MODE is enabled — JWT verification skipped. Do not use in production.")
        return {"sub": "dev-user", "dev_mode": True}

    if credentials is None:
        raise HTTPException(status_code=401, detail="Authorization header required")

    token = credentials.credentials
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            raise HTTPException(status_code=401, detail="Token missing 'kid' header")

        key = _find_key(kid)
        if key is None:
            raise HTTPException(status_code=401, detail="Signing key not found")

        payload = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=OIDC_AUDIENCE,
            issuer=OIDC_ISSUER,
        )
        return payload

    except HTTPException:
        raise
    except JWTError as e:
        logger.warning(f"JWT validation failed: {e}")
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    except Exception as e:
        logger.error(f"Unexpected auth error: {e}")
        raise HTTPException(status_code=401, detail="Authentication error")
