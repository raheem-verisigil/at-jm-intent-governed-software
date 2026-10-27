# AT-JM — Intent-Governed Software Runtime

AT-JM is an early-stage runtime for expressing software-change intent, evaluating structured requests against explicit boundaries, and making evidence gaps visible before release.

## Current prototype capabilities

- `GET /api/health` — service health and declared capabilities.
- `GET /api/demo-contract` — sample intent contract.
- `POST /api/contract/validate` — basic contract shape validation.
- `POST /api/policy/evaluate` — bounded deterministic evaluation.
- `GET /api/admin/ledger/verify` — verifies the local audit hash chain; requires `X-ATJM-Admin-Token`.
- Commercial site and interactive policy demo at `/`.

## Run locally

Requires Python 3.12+; no third-party dependencies.

```bash
python -m unittest discover -s tests -v
python app.py
```

Open http://localhost:8080.

## Policy request example

```json
{"action":"read_source","environment":"development","risk_level":"low","evidence_status":"passed","contract_rule":"standard"}
```

## Decision metadata ledger

Policy evaluations are recorded in SQLite as a hash-chained sequence. The ledger stores a SHA-256 digest of the submitted inputs, not the raw policy input payload. Set `ATJM_DATA_DIR` to a persistent directory and ensure the process can write to it. On Railway, mount a persistent volume at `/data`; the Docker image defaults `ATJM_DATA_DIR=/data`.

Set `ATJM_ADMIN_TOKEN` to a long, randomly generated secret to enable the administrative chain-verification endpoint. Without this variable, verification requests are unauthorized. Never commit the token to source control or expose it in browser code.

The local hash chain can detect altered records and interior deletion/reordering. It cannot independently detect deletion of the final records without a separately retained checkpoint or external anchor. SQLite is intended for a single application replica; use PostgreSQL and a separately anchored audit design before horizontal scaling or high-assurance deployments.

## Important limitations

This remains an early-stage prototype, not a security-audited product. It does not authenticate end users, enforce customer tenancy, authenticate contract approvals, verify evidence provenance, execute code or actions, integrate with GitHub pull requests, or enforce controls on external systems. The caller supplies policy inputs; an `ALLOW` response is not authorization to execute a real action. Do not send secrets or confidential data. Rate limiting is in-process and is not a substitute for edge-level controls.
