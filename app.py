import hmac
import json
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import auth as authn
import contracts_store
from audit_ledger import append_decision, verify_chain

ROOT = Path(__file__).resolve().parent
MAX_BODY_BYTES = 1_000_000
RATE_LIMIT_WINDOW_SECONDS = 60
RATE_LIMIT_REQUESTS = 90
_rate_lock = threading.Lock()
_rate_buckets = {}

ACTIONS = {
    "read_source", "edit_candidate_code", "run_tests_in_sandbox", "deploy",
    "delete", "external", "credentials", "charge_real_customer",
    "modify_production_credentials",
}
ENVIRONMENTS = {"development", "staging", "production"}
RISKS = {"low", "medium", "high"}
EVIDENCE = {"passed", "failed", "missing", "conflicting"}
RULES = {"standard", "noExternal", "noProd"}

DEMO = {
    "contract_version": "0.1",
    "contract_id": "atjm-demo-001",
    "status": "draft",
    "goal": {
        "statement": "Add subscription billing without duplicate charges",
        "acceptance_criteria": [{
            "id": "AC-001",
            "description": "Repeated billing events do not create duplicate charges",
            "verification": "automated_test",
            "required": True,
        }],
    },
    "invariants": [{
        "id": "INV-001",
        "rule": "A billing event must not create duplicate charges",
        "severity": "critical",
    }],
    "prohibitions": [{
        "id": "PRO-001",
        "rule": "Do not access production payment credentials from development",
        "severity": "critical",
    }],
    "authority": {
        "allowed_actions": ["read_source", "edit_candidate_code", "run_tests_in_sandbox"],
        "denied_actions": ["charge_real_customer", "modify_production_credentials"],
        "human_approval_required_for": ["production_deployment", "real_payment_execution"],
    },
    "verification": {
        "required_checks": ["acceptance_tests", "invariant_tests", "security_checks", "regression_tests"],
    },
    "evidence": {
        "record_contract_version": True,
        "record_source_changes": True,
        "record_tool_actions": True,
        "record_test_results": True,
    },
    "change_control": {
        "material_change_requires_revalidation": True,
        "contract_amendment_requires_authorization": True,
    },
}


def validate_contract(contract):
    if not isinstance(contract, dict):
        return {"valid": False, "errors": ["Contract must be a JSON object."]}
    required = {
        "contract_version", "contract_id", "status", "goal", "invariants",
        "prohibitions", "authority", "verification", "evidence", "change_control",
    }
    errors = []
    missing = required - contract.keys()
    if missing:
        errors.append("Missing fields: " + ", ".join(sorted(missing)) + ".")
    if contract.get("contract_version") != "0.1":
        errors.append("contract_version must be '0.1'.")
    contract_id = contract.get("contract_id")
    if not isinstance(contract_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}", contract_id):
        errors.append("contract_id format is invalid.")
    if contract.get("status") not in {"draft", "approved", "retired"}:
        errors.append("status must be draft, approved or retired.")
    goal = contract.get("goal")
    if not isinstance(goal, dict) or not isinstance(goal.get("statement"), str) or not goal["statement"].strip():
        errors.append("goal.statement must be non-empty.")
    if not isinstance(goal, dict) or not isinstance(goal.get("acceptance_criteria"), list) or not goal["acceptance_criteria"]:
        errors.append("goal.acceptance_criteria must be a non-empty array.")
    for key in ("invariants", "prohibitions"):
        if not isinstance(contract.get(key), list):
            errors.append(key + " must be an array.")
    for key in ("authority", "verification", "evidence", "change_control"):
        if not isinstance(contract.get(key), dict):
            errors.append(key + " must be an object.")
    if errors:
        return {"valid": False, "errors": errors, "validator_version": "0.1.1"}
    return {
        "valid": True,
        "contract_id": contract["contract_id"],
        "contract_version": "0.1",
        "status": contract["status"],
        "acceptance_criteria_count": len(goal["acceptance_criteria"]),
        "validator_version": "0.1.1",
        "warnings": [
            "Draft contracts are not release authority.",
            "Contract approval is not authenticated in this release.",
        ],
    }


def result(decision, reason, payload, next_steps):
    return {
        "schema_version": "0.1",
        "decision_id": "dec-" + uuid.uuid4().hex,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "decision": decision,
        "reason": reason,
        "inputs": payload,
        "next_steps": next_steps,
        "execution_performed": False,
        "limitations": [
            "No identity verification",
            "No external system access",
            "No code execution",
            "Not production authorization",
        ],
    }


def evaluate(payload):
    if not isinstance(payload, dict):
        return result("ERROR", "Request must be a JSON object.", None, ["Send structured JSON."])
    required = {"action", "environment", "risk_level", "evidence_status", "contract_rule"}
    missing = required - payload.keys()
    if missing:
        return result("INDETERMINATE", "Missing inputs: " + ", ".join(sorted(missing)), payload, ["Provide every required input."])
    if (
        payload["action"] not in ACTIONS
        or payload["environment"] not in ENVIRONMENTS
        or payload["risk_level"] not in RISKS
        or payload["evidence_status"] not in EVIDENCE
        or payload["contract_rule"] not in RULES
    ):
        return result("INDETERMINATE", "Unknown policy input value.", payload, ["Use supported values."])
    action, environment, risk, evidence, rule = (
        payload[key] for key in ("action", "environment", "risk_level", "evidence_status", "contract_rule")
    )
    if evidence in {"failed", "conflicting"}:
        return result("DENY", "Evidence failed or is contradictory.", payload, ["Resolve evidence issues and rerun checks."])
    if action in {"delete", "credentials", "charge_real_customer", "modify_production_credentials"}:
        return result("DENY", "Prototype hard-prohibition policy blocks this action.", payload, ["Use a separately designed authorized workflow."])
    if rule == "noExternal" and action == "external":
        return result("DENY", "Contract rule prohibits external data transfer.", payload, ["Keep data within the approved boundary."])
    if rule == "noProd" and environment == "production" and action in {"deploy", "edit_candidate_code", "external"}:
        return result("DENY", "Contract rule prohibits mutation in production.", payload, ["Use non-production or amend the contract through authorized review."])
    if evidence == "missing":
        return result("INDETERMINATE", "Required evidence is missing.", payload, ["Collect evidence or escalate."])
    if action == "deploy" or environment == "production" or risk == "high" or action == "external":
        return result("REQUIRE_APPROVAL", "Sensitive or high-impact action requires human review.", payload, ["Review scope, evidence, contract version and rollback plan."])
    if action not in {"read_source", "edit_candidate_code", "run_tests_in_sandbox"}:
        return result("DENY", "Action is not in the prototype permitted set.", payload, ["Declare and review capability before requesting it."])
    return result("ALLOW", "Structured request passes prototype rules.", payload, ["Policy result only; no action was executed."])


def _rate_limited(client_ip):
    now = time.monotonic()
    with _rate_lock:
        bucket = [stamp for stamp in _rate_buckets.get(client_ip, []) if now - stamp < RATE_LIMIT_WINDOW_SECONDS]
        if len(bucket) >= RATE_LIMIT_REQUESTS:
            _rate_buckets[client_ip] = bucket
            return True
        bucket.append(now)
        _rate_buckets[client_ip] = bucket
        if len(_rate_buckets) > 5000:
            for ip in list(_rate_buckets)[:1000]:
                _rate_buckets.pop(ip, None)
        return False


class Handler(BaseHTTPRequestHandler):
    server_version = "ATJMRuntime"
    sys_version = ""

    def send_json(self, status, obj, extra_headers=None):
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
        self.send_header("X-Frame-Options", "DENY")
        for header, value in (extra_headers or {}).items():
            self.send_header(header, value)
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self):
        content_length = self.headers.get("Content-Length", "")
        try:
            size = int(content_length)
        except (TypeError, ValueError):
            self.send_json(400, {"error": "A valid Content-Length is required."})
            return None
        if size < 1 or size > MAX_BODY_BYTES:
            self.send_json(413 if size > MAX_BODY_BYTES else 400, {"error": "Body must be between 1 byte and 1 MB."})
            return None
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self.send_json(415, {"error": "Content-Type must be application/json."})
            return None
        try:
            return json.loads(self.rfile.read(size))
        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "Body must be valid JSON."})
            return None

    def _authenticate(self, required_permission=None):
        try:
            identity = authn.verify_bearer_token(self.headers.get("Authorization"))
        except authn.AuthUnavailable:
            self.send_json(503, {"error": "Protected management API is not configured for OIDC authentication."})
            return None
        except authn.AuthRejected:
            self.send_json(401, {"error": "A valid authenticated identity and tenant claim are required."})
            return None
        if required_permission and required_permission not in identity["roles"]:
            self.send_json(403, {"error": "Insufficient permission."})
            return None
        return identity

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/contracts" or path.startswith("/api/contracts/"):
            if _rate_limited(self.client_address[0]):
                return self.send_json(429, {"error": "Rate limit exceeded. Try again shortly."}, {"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)})
            identity = self._authenticate()
            if identity is None:
                return
            if path == "/api/contracts":
                return self.send_json(200, {"contracts": contracts_store.list_latest(identity["tenant_id"])})
            match = re.fullmatch(r"/api/contracts/([A-Za-z0-9][A-Za-z0-9._-]{2,127})", path)
            if match:
                record = contracts_store.get_latest(identity["tenant_id"], match.group(1))
                if record is None:
                    return self.send_json(404, {"error": "Contract not found."})
                return self.send_json(200, record)
            return self.send_json(404, {"error": "Not found"})
        if path == "/api/health":
            return self.send_json(200, {
                "status": "ok",
                "service": "AT-JM Promise Runtime",
                "version": "0.3.0",
                "capabilities": ["contract_validation", "bounded_policy_evaluation", "decision_metadata_ledger", "tenant_scoped_contract_versions"],
                "oidc_management_configured": bool(os.environ.get("ATJM_OIDC_ISSUER") and os.environ.get("ATJM_OIDC_AUDIENCE") and os.environ.get("ATJM_OIDC_JWKS_URL")),
                "execution_performed": False,
            })
        if path == "/api/demo-contract":
            return self.send_json(200, DEMO)
        if path == "/api/admin/ledger/verify":
            token = os.environ.get("ATJM_ADMIN_TOKEN", "")
            supplied = self.headers.get("X-ATJM-Admin-Token", "")
            if not token or not hmac.compare_digest(token, supplied):
                return self.send_json(401, {"error": "Unauthorized."})
            return self.send_json(200, verify_chain())
        if path in {"/", "/index.html"}:
            try:
                body = (ROOT / "index.html").read_bytes()
            except OSError:
                return self.send_json(500, {"error": "Website file unavailable."})
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.send_header("X-Frame-Options", "DENY")
            self.end_headers()
            self.wfile.write(body)
            return
        return self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        path = urlsplit(self.path).path
        approval_match = re.fullmatch(r"/api/contracts/([A-Za-z0-9][A-Za-z0-9._-]{2,127})/approve", path)
        if path not in {"/api/contract/validate", "/api/policy/evaluate", "/api/contracts"} and not approval_match:
            return self.send_json(404, {"error": "Not found"})
        if _rate_limited(self.client_address[0]):
            return self.send_json(429, {"error": "Rate limit exceeded. Try again shortly."}, {"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)})
        payload = self._read_json()
        if payload is None:
            return
        if path == "/api/contract/validate":
            validated = validate_contract(payload)
            return self.send_json(200 if validated["valid"] else 422, validated)
        if path == "/api/contracts":
            identity = self._authenticate()
            if identity is None:
                return
            validated = validate_contract(payload)
            if not validated["valid"]:
                return self.send_json(422, validated)
            if payload.get("status") != "draft":
                return self.send_json(422, {"valid": False, "errors": ["New contract versions must be submitted with status draft."]})
            try:
                record = contracts_store.create_draft(identity["tenant_id"], payload, identity["subject"])
            except Exception:
                return self.send_json(503, {"error": "Contract version could not be stored.", "retryable": True})
            return self.send_json(201, record)
        if approval_match:
            required_permission = os.environ.get("ATJM_APPROVAL_PERMISSION", "atjm:contracts:approve")
            identity = self._authenticate(required_permission)
            if identity is None:
                return
            if payload != {}:
                return self.send_json(400, {"error": "Approval endpoint expects an empty JSON object."})
            contract_id = approval_match.group(1)
            try:
                record = contracts_store.approve_latest(identity["tenant_id"], contract_id, identity["subject"])
            except LookupError:
                return self.send_json(404, {"error": "Contract not found."})
            except PermissionError:
                return self.send_json(403, {"error": "A different authorized user must approve this contract."})
            except ValueError as exc:
                return self.send_json(409, {"error": str(exc)})
            except Exception:
                return self.send_json(503, {"error": "Contract approval could not be stored.", "retryable": True})
            return self.send_json(200, record)
        decision = evaluate(payload)
        try:
            ledger_metadata = append_decision(decision, payload)
        except Exception:
            # Do not report a decision as durably recorded if the ledger write failed.
            return self.send_json(503, {
                "error": "Decision could not be durably recorded.",
                "decision_returned": False,
                "retryable": True,
            })
        decision["audit"] = {
            "recorded": True,
            "sequence": ledger_metadata["sequence"],
            "entry_hash": ledger_metadata["entry_hash"],
            "input_sha256": ledger_metadata["input_sha256"],
        }
        return self.send_json(200, decision)

    def log_message(self, fmt, *args):
        # Avoid logging request bodies or sensitive query strings.
        print("%s %s %s" % (self.log_date_time_string(), self.command, urlsplit(self.path).path))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
