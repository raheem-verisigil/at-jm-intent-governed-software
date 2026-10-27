# AT-JM — Intent-Governed Software Runtime

AT-JM is an early-stage runtime for expressing software-change intent, evaluating structured requests against explicit boundaries, and making evidence gaps visible before release.

## Current capabilities

- `GET /api/health` — service health and whether OIDC management configuration is present.
- `GET /api/demo-contract` — sample intent contract.
- `POST /api/contract/validate` — basic contract-shape validation.
- `POST /api/policy/evaluate` — bounded deterministic evaluation; records decision metadata.
- `GET /api/admin/ledger/verify` — verifies the local audit hash chain; requires `X-ATJM-Admin-Token`.
- OIDC-protected contract APIs: `GET/POST /api/contracts`, `GET /api/contracts/{contract_id}`, `POST /api/contracts/{contract_id}/approve`. These return `503` until OIDC settings are configured.
- Early GitHub Actions intent gate template in `integrations/github/`.
- Commercial site and interactive policy demo at `/`.

## Run locally

Requires Python 3.12+.

```bash
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python app.py
```

Open http://localhost:8080.

## Policy request example

```json
{"action":"read_source","environment":"development","risk_level":"low","evidence_status":"passed","contract_rule":"standard"}
```

## Persistent decision metadata

Policy evaluations are recorded in SQLite as a hash-chained sequence. The ledger stores a SHA-256 digest of submitted inputs rather than the raw input payload. Set `ATJM_DATA_DIR` to a persistent directory. On Railway, mount a persistent volume at `/data`; the Docker image defaults `ATJM_DATA_DIR=/data`.

Set `ATJM_ADMIN_TOKEN` to a long, randomly generated secret to enable the administrative chain-verification endpoint. Never commit the token to source control or expose it in browser code.

The local hash chain can detect altered records and interior deletion/reordering. It cannot independently detect deletion of the final records without a separately retained checkpoint or external anchor. SQLite is intended for a single application replica; use PostgreSQL and a separately anchored audit design before horizontal scaling or high-assurance deployments.

## OIDC contract management

See [OIDC contract API configuration](docs/oidc-contract-api.md) for the required issuer, audience, JWKS URL, tenant claim and approval permission settings. Tenant identifiers are derived from verified tokens, not from request payloads. Protected management routes fail closed until OIDC is configured.

## GitHub pull-request gate

See [GitHub Intent Gate setup](integrations/github/README.md). The current integration checks an approved base-branch contract, prohibited file-path patterns and change size. It does not semantically prove code correctness or verify other CI checks; configure those separately as required GitHub checks.

## Security and product boundaries

AT-JM is still an early-stage prototype and has not undergone an independent security audit. It does not execute code or actions, verify evidence provenance, or enforce controls on external deployment systems. The public policy demo accepts caller-supplied inputs; an `ALLOW` response is not authorization to execute a real action. Do not send secrets or confidential data.

The OIDC contract API is the first authenticated management slice, not a complete identity rollout. Tenant provisioning, user invitations, a management UI, GitHub App credentials, PostgreSQL migration, external audit checkpoints, backup-restore drills and a security review remain before a broad production launch.
