"""OIDC JWT verification for AT-JM management APIs."""
from __future__ import annotations
import os
from typing import Any
import jwt
from jwt import PyJWKClient

class AuthUnavailable(Exception):
    """Authentication is not configured correctly."""
class AuthRejected(Exception):
    """Identity or token was rejected."""

_clients: dict[str, PyJWKClient] = {}

def _https(name: str) -> str:
    value=os.environ.get(name,"").strip()
    if not value.startswith("https://"):
        raise AuthUnavailable(f"{name} must be configured as an HTTPS URL.")
    return value

def verify_signed_jwt(token: str, audience: str, issuer: str) -> dict[str, Any]:
    if not token or len(token)>16384: raise AuthRejected("Token is invalid.")
    jwks=_https("ATJM_OIDC_JWKS_URL")
    try:
        client=_clients.get(jwks)
        if client is None:
            client=PyJWKClient(jwks,cache_jwk_set=True,lifespan=300,timeout=4)
            _clients[jwks]=client
        key=client.get_signing_key_from_jwt(token)
        return jwt.decode(token,key.key,algorithms=["RS256"],audience=audience,issuer=issuer,
                          options={"require":["exp","iat","sub"]},leeway=30)
    except (AuthUnavailable,AuthRejected): raise
    except Exception as exc: raise AuthRejected("Token could not be validated.") from exc

def verify_access_token(token: str) -> dict[str, Any]:
    issuer=_https("ATJM_OIDC_ISSUER")
    audience=os.environ.get("ATJM_OIDC_AUDIENCE","").strip()
    if not audience: raise AuthUnavailable("ATJM_OIDC_AUDIENCE is not configured.")
    claims=verify_signed_jwt(token,audience,issuer)
    subject=claims.get("sub")
    if not isinstance(subject,str) or not subject.strip(): raise AuthRejected("Token subject is missing.")
    tenant_claim=os.environ.get("ATJM_TENANT_CLAIM","https://at-jm.ai/tenant_id")
    tenant=claims.get(tenant_claim)
    if not isinstance(tenant,str) or not tenant.strip() or len(tenant)>256:
        raise AuthRejected("Token does not include the configured tenant claim.")
    role_claim=os.environ.get("ATJM_ROLE_CLAIM","permissions")
    roles=claims.get(role_claim,[])
    if isinstance(roles,str): roles=[roles]
    if not isinstance(roles,list) or any(not isinstance(x,str) for x in roles):
        raise AuthRejected("Token permissions claim has invalid format.")
    return {"subject":subject,"tenant_id":tenant,"roles":roles,"claims":claims}

def verify_bearer_token(authorization: str | None) -> dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise AuthRejected("A bearer token is required.")
    return verify_access_token(authorization[7:].strip())
