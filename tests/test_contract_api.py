import copy
import http.client
import json
import os
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import ThreadingHTTPServer

import app
import auth


class ContractApiIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {
            "ATJM_DATA_DIR": self.tempdir.name,
            "ATJM_APPROVAL_PERMISSION": "atjm:contracts:approve",
        })
        self.env.start()

        def fake_verify(authorization):
            identities = {
                "Bearer tenant-a-alice": {"subject": "alice", "tenant_id": "tenant-a", "roles": [], "claims": {}},
                "Bearer tenant-a-bob": {"subject": "bob", "tenant_id": "tenant-a", "roles": ["atjm:contracts:approve"], "claims": {}},
                "Bearer tenant-b-bob": {"subject": "bob", "tenant_id": "tenant-b", "roles": ["atjm:contracts:approve"], "claims": {}},
            }
            if authorization not in identities:
                raise auth.AuthRejected("invalid test token")
            return identities[authorization]

        self.verify_patch = patch("app.authn.verify_bearer_token", side_effect=fake_verify)
        self.verify_patch.start()
        self.rate_patch = patch("app._rate_limited", return_value=False)
        self.rate_patch.start()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), app.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_address[1]

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.rate_patch.stop()
        self.verify_patch.stop()
        self.env.stop()
        self.tempdir.cleanup()

    def request(self, method, path, token=None, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        headers = {}
        encoded = None
        if body is not None:
            encoded = json.dumps(body)
            headers["Content-Type"] = "application/json"
        if token:
            headers["Authorization"] = token
        connection.request(method, path, body=encoded, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        result = json.loads(payload) if payload else None
        status = response.status
        connection.close()
        return status, result

    def sample_contract(self):
        contract = copy.deepcopy(app.DEMO)
        contract["contract_id"] = "atjm-contract-api-test"
        contract["status"] = "draft"
        return contract

    def test_contract_routes_require_identity(self):
        status, _ = self.request("GET", "/api/contracts")
        self.assertEqual(status, 401)

    def test_caller_cannot_submit_contract_as_already_approved(self):
        candidate = self.sample_contract()
        candidate["status"] = "approved"
        status, body = self.request("POST", "/api/contracts", "Bearer tenant-a-alice", candidate)
        self.assertEqual(status, 422)
        self.assertIn("draft", body["errors"][0])

    def test_contract_isolated_by_tenant(self):
        status, created = self.request("POST", "/api/contracts", "Bearer tenant-a-alice", self.sample_contract())
        self.assertEqual(status, 201)
        self.assertEqual(created["tenant_id"], "tenant-a")
        status, _ = self.request("GET", "/api/contracts/atjm-contract-api-test", "Bearer tenant-b-bob")
        self.assertEqual(status, 404)

    def test_approval_requires_permission_and_independent_actor(self):
        self.request("POST", "/api/contracts", "Bearer tenant-a-alice", self.sample_contract())
        status, _ = self.request("POST", "/api/contracts/atjm-contract-api-test/approve", "Bearer tenant-a-alice", {})
        self.assertEqual(status, 403)
        status, approved = self.request("POST", "/api/contracts/atjm-contract-api-test/approve", "Bearer tenant-a-bob", {})
        self.assertEqual(status, 200)
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["version"], 2)

    def test_missing_oidc_config_fails_closed(self):
        with patch("app.authn.verify_bearer_token", side_effect=auth.AuthUnavailable("not configured")):
            status, body = self.request("GET", "/api/contracts")
        self.assertEqual(status, 503)
        self.assertIn("not configured", body["error"])


if __name__ == "__main__":
    unittest.main()
