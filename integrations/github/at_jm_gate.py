#!/usr/bin/env python3
"""AT-JM pull-request gate (early integration).

Reads the approved contract from the PR base branch, never from the proposed
head. Enforces contract validity, immutable contract changes, prohibited path
patterns, and a maximum changed-file count. It does not inspect source-code
semantics or verify third-party CI checks.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

CONTRACT_PATH = ".at-jm/intent.json"
SCHEMA_VERSION = "1.0"
CONTRACT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
REF_RE = re.compile(r"^[A-Za-z0-9._/-]{1,200}$")
SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")


def validate_contract(contract: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(contract, dict):
        return ["Intent contract must be a JSON object."]
    if contract.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be '{SCHEMA_VERSION}'.")
    contract_id = contract.get("contract_id")
    if not isinstance(contract_id, str) or not CONTRACT_ID_RE.fullmatch(contract_id):
        errors.append("contract_id must be a 3–128 character identifier using letters, numbers, '.', '_' or '-'.")
    if contract.get("status") != "approved":
        errors.append("Contract status must be 'approved' on the base branch.")
    intent = contract.get("intent")
    if not isinstance(intent, dict) or not isinstance(intent.get("statement"), str) or not intent["statement"].strip():
        errors.append("intent.statement must be a non-empty string.")
    policy = contract.get("policy")
    if not isinstance(policy, dict):
        errors.append("policy must be an object.")
        return errors
    prohibited = policy.get("prohibited_paths")
    if not isinstance(prohibited, list) or any(not isinstance(p, str) or not p.strip() for p in prohibited):
        errors.append("policy.prohibited_paths must be an array of non-empty glob patterns.")
    max_files = policy.get("max_changed_files")
    if isinstance(max_files, bool) or not isinstance(max_files, int) or not 1 <= max_files <= 1000:
        errors.append("policy.max_changed_files must be an integer between 1 and 1000.")
    return errors


def evaluate_changes(contract: dict[str, Any], changed_paths: list[str]) -> dict[str, Any]:
    errors = validate_contract(contract)
    if errors:
        return {"passed": False, "errors": errors, "changed_files": len(changed_paths)}
    if CONTRACT_PATH in changed_paths:
        errors.append(
            f"{CONTRACT_PATH} cannot be changed in the same pull request it governs; "
            "submit an independently reviewed contract change first."
        )
    policy = contract["policy"]
    maximum = policy["max_changed_files"]
    if len(changed_paths) > maximum:
        errors.append(f"Changed file count {len(changed_paths)} exceeds contract limit {maximum}.")
    prohibited = policy["prohibited_paths"]
    violations = sorted(
        path for path in changed_paths
        if any(fnmatch.fnmatchcase(path, pattern) for pattern in prohibited)
    )
    if violations:
        errors.append("Changes touch prohibited paths: " + ", ".join(violations))
    return {
        "passed": not errors,
        "errors": errors,
        "changed_files": len(changed_paths),
        "prohibited_path_matches": violations,
        "contract_id": contract.get("contract_id"),
        "contract_version": contract.get("schema_version"),
    }


def run_git(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    return completed.stdout


def read_base_contract(base_ref: str) -> dict[str, Any]:
    if not REF_RE.fullmatch(base_ref) or ".." in base_ref or base_ref.startswith("-"):
        raise ValueError("Invalid base ref.")
    raw = run_git("show", f"origin/{base_ref}:{CONTRACT_PATH}")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise ValueError("Base intent contract must be a JSON object.")
    return parsed


def changed_paths(base_ref: str, head_sha: str) -> list[str]:
    if not REF_RE.fullmatch(base_ref) or ".." in base_ref or base_ref.startswith("-"):
        raise ValueError("Invalid base ref.")
    if not SHA_RE.fullmatch(head_sha):
        raise ValueError("Invalid head SHA.")
    output = run_git("diff", "--name-only", "--diff-filter=ACMR", f"origin/{base_ref}...{head_sha}")
    return sorted({line.strip() for line in output.splitlines() if line.strip()})


def write_summary(report: dict[str, Any]) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    status = "PASS" if report.get("passed") else "BLOCKED"
    lines = [
        f"## AT-JM Intent Gate: {status}",
        "",
        f"- Contract: `{report.get('contract_id', 'unavailable')}`",
        f"- Changed files: {report.get('changed_files', 0)}",
        "",
    ]
    if report.get("errors"):
        lines.extend(["### Reasons", *[f"- {error}" for error in report["errors"]], ""])
    Path(summary_path).write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    base_ref = os.environ.get("GITHUB_BASE_REF", "")
    head_sha = os.environ.get("GITHUB_SHA", "")
    try:
        contract = read_base_contract(base_ref)
        paths = changed_paths(base_ref, head_sha)
        report = evaluate_changes(contract, paths)
    except (ValueError, OSError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        report = {
            "passed": False,
            "changed_files": 0,
            "errors": [f"Gate could not establish a trustworthy evaluation: {type(exc).__name__}: {exc}"],
        }
    print(json.dumps(report, indent=2, sort_keys=True))
    write_summary(report)
    return 0 if report.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
