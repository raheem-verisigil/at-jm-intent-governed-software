# OIDC-protected intent contract API

This release adds a provider-neutral OIDC JWT boundary for the contract-management API. It is disabled until the OIDC settings below are configured. Do not use placeholder values in production.

## Required Railway variables

- `ATJM_OIDC_ISSUER`: exact HTTPS issuer URL expected in the token's `iss` claim.
- `ATJM_OIDC_AUDIENCE`: API audience expected in the token's `aud` claim.
- `ATJM_OIDC_JWKS_URL`: HTTPS JWKS endpoint for the issuer's signing keys.

Optional claim/policy settings:

- `ATJM_TENANT_CLAIM`: tenant claim name; defaults to `tenant_id`. The verified token must include a non-empty string claim.
- `ATJM_ROLE_CLAIM`: permissions claim name; defaults to `permissions`. It may be a list of strings or one string.
- `ATJM_APPROVAL_PERMISSION`: required permission for approvals; defaults to `atjm:contracts:approve`.

The verifier accepts RS256 tokens only, validates signature, issuer, audience and required `exp`, `iat`, and `sub` claims, and applies a 30-second clock-skew allowance. It rejects missing tenant claims and non-HTTPS issuer/JWKS URLs. Configure the provider to issue an explicit tenant identifier and a permission claim for contract approvers. Do not infer tenant identity from user-supplied request fields.

## Routes

- `GET /api/contracts` — list latest contract version per ID for the authenticated tenant.
- `POST /api/contracts` — create a new immutable draft version from a valid contract JSON body.
- `GET /api/contracts/{contract_id}` — read the latest version for the authenticated tenant.
- `POST /api/contracts/{contract_id}/approve` — approve the latest draft, requiring the configured permission and a different subject from the draft creator. Send an empty JSON object as the body.

Contract versions are stored in the SQLite database under `ATJM_DATA_DIR`. Every version records a canonical content SHA-256 digest, actor, timestamp and status. Approval creates a new immutable version instead of overwriting the draft. Tenant identifiers are always derived from the verified token.

## Before enabling for a pilot

1. Configure and test the issuer, audience and JWKS values in a non-production environment.
2. Confirm the tenant claim cannot be selected or changed by the API caller.
3. Confirm only designated approvers receive `atjm:contracts:approve`.
4. Test invalid/expired/wrong-audience tokens, missing tenant claims, cross-tenant reads, self-approval and concurrent version creation.
5. Review data retention and backup/restore for the persistent Railway volume.

## Current limitations

This is the first authenticated contract API slice, not a completed identity rollout. The live service will return `503` for protected contract routes until the OIDC settings are configured. It does not yet provide a user interface for contract management, organization provisioning, invitation flows, SSO administration, GitHub App credentials, or an external audit checkpoint. SQLite supports a single application replica; migrate to PostgreSQL before horizontal scaling. A security review is still required before treating this as a production security control.
