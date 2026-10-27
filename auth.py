"""OIDC JWT verification for protected AT-JM management endpoints."""
from __future__ import annotations

import os
from typing import Any

import jwt
from jwt import PyJWKClient


class AuthUnavailable(Exception):
    """Authentication is not configured correctly on the service."""


class AuthRejected(Exception):
    """The request does not carry a valid authorized identity."""


_jwks_clients: dict[str, PyJWKClient] = {}


def verify_bearer_token(authorization: str | None) -> dict[str, Any]:
    issuer = os.environ.get("ATJM_OIDC_ISSUER", "").strip()
    audience = os.environ.get("ATJM_OIDC_AUDIENCE", "").strip()
    jwks_url = os.environ.get("ATJM_OIDC_JWKS_URL", "").strip()
    if not issuer or not audience or not jwks_url:
        raise AuthUnavailable("OIDC authentication is not configured.")
    if not issuer.startswith("https://") or not jwks_url.startswith("https://"):
        raise AuthUnavailable("OIDC issuer and JWKS URL must use HTTPS.")
    if not authorization or not authorization.startswith("Bearer "):
        raise AuthRejected("A bearer token is required.")
    token = authorization[7:].strip()
    if not token or len(token) > 16384:
        raise AuthRejected("Bearer token is invalid.")
    try:
        client = _jwks_clients.get(jwks_url)
        if client is None:
            client = PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=300, timeout=4)
            _jwks_clients[jwks_url] = client
        signing_key = client.get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=audience,
            issuer=issuer,
            options={"require": ["exp", "iat", "sub"]},
            leeway=30,
        )
    except AuthRejected:
        raise
    except Exception as exc:
        raise AuthRejected("Bearer token could not be validated.") from exc
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise AuthRejected("Token subject is missing.")
    tenant_claim = os.environ.get("ATJM_TENANT_CLAIM", "tenant_id")
    tenant_id = claims.get(tenant_claim)
    if not isinstance(tenant_id, str) or not tenant_id.strip() or len(tenant_id) > 256:
        raise AuthRejected("Token does not include the configured tenant claim.")
    role_claim = os.environ.get("ATJM_ROLE_CLAIM", "permissions")
    roles = claims.get(role_claim, [])
    if isinstance(roles, str):
        roles = [roles]
    if not isinstance(roles, list) or any(not isinstance(role, str) for role in roles):
        raise AuthRejected("Token role claim has an invalid format.")
    return {"subject": subject, "tenant_id": tenant_id, "roles": roles, "claims": claims}
