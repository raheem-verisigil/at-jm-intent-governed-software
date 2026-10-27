# AT-JM — Intent-Governed Software Runtime

AT-JM explores a runtime layer for expressing software-change intent, evaluating structured requests against explicit boundaries, and making evidence gaps visible before release.

## Prototype v0.1
- JSON contract-shape validation: `POST /api/contract/validate`
- Bounded deterministic policy evaluation: `POST /api/policy/evaluate`
- Health: `GET /api/health`
- Example contract: `GET /api/demo-contract`
- Commercial site and interactive policy demo at `/`

## Run locally
Requires Python 3.12+; no third-party dependencies.

```bash
python app.py
python -m unittest discover -s tests -v
```

Open http://localhost:8080.

## Policy request example
```json
{"action":"read_source","environment":"development","risk_level":"low","evidence_status":"passed","contract_rule":"standard"}
```

## Important limitations
This is an early prototype, not a security-audited product. It does not execute code or actions, authenticate users or approvals, verify evidence provenance, persist an evidence ledger, or enforce controls on external systems. The caller supplies policy inputs; an `ALLOW` response is not authorization to execute an action in a real environment. Do not send secrets or confidential data.
