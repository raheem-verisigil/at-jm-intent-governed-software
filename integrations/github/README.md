# AT-JM GitHub Intent Gate — early integration

This integration is a **deterministic pull-request boundary check**, not a GitHub App and not a semantic proof that code matches a business requirement.

## What it currently enforces

- Reads `.at-jm/intent.json` from the PR **base branch**, not from the proposed change.
- Fails closed if the approved contract is missing, invalid, or not marked `approved`.
- Blocks a PR that changes `.at-jm/intent.json` and the application change together. Contract changes need a separate reviewed change.
- Blocks paths matching `policy.prohibited_paths`.
- Enforces `policy.max_changed_files`.
- Writes a concise GitHub Actions step summary and returns a failing exit code when blocked.

## Install in a pilot repository

1. Copy `integrations/github/intent.example.json` to `.at-jm/intent.json` in the pilot repository.
2. Replace the sample intent, prohibited paths, and file limit with rules the team has reviewed. Have the team approve and merge this contract first.
3. Copy `integrations/github/at_jm_gate.py` into the pilot repository at `integrations/github/at_jm_gate.py`.
4. Copy `integrations/github/at-jm-gate.workflow.example.yml` to `.github/workflows/at-jm-gate.yml`.
5. Open a test PR that changes a permitted file, then test a prohibited path and a contract modification. Configure the resulting `AT-JM / Intent Gate` check as required in GitHub branch protection.

## Important setup detail

The approved contract must already exist on the base branch before the gate workflow is introduced. The gate intentionally does not trust a contract that is introduced or edited by the same PR it is evaluating.

## Limits in this version

- This gate evaluates path patterns and change size. It does not understand program semantics or prove that code satisfies natural-language intent.
- It does not verify that other CI checks passed. Configure those checks as separate required GitHub checks.
- It does not create or authenticate human approvals, verify evidence provenance, or authorize deployment.
- The example workflow is intentionally stored outside `.github/workflows/` in this repository so it does not activate as a live gate here.
- Path patterns are policy inputs; review them carefully and test bypass cases before enabling the gate on a sensitive repository.

Treat this as an early design-partner integration until it has been tested in a separate pilot repository and independently reviewed.
