import os
import tempfile
import unittest
from unittest.mock import patch

import contracts_store


class ContractStoreTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"ATJM_DATA_DIR": self.tempdir.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tempdir.cleanup()

    def contract(self, contract_id="atjm-contract-001"):
        return {
            "contract_version": "0.1",
            "contract_id": contract_id,
            "status": "draft",
            "goal": {"statement": "Keep the intended behavior intact", "acceptance_criteria": [{"id": "AC-1"}]},
            "invariants": [],
            "prohibitions": [],
            "authority": {},
            "verification": {},
            "evidence": {},
            "change_control": {},
        }

    def test_draft_versions_are_immutable_and_increment(self):
        first = contracts_store.create_draft("tenant-a", self.contract(), "alice")
        second = contracts_store.create_draft("tenant-a", self.contract(), "alice")
        self.assertEqual(first["version"], 1)
        self.assertEqual(second["version"], 2)
        self.assertEqual(first["status"], "draft")
        self.assertNotEqual(first["created_at"], "")

    def test_tenant_scoping_hides_other_tenant_records(self):
        contracts_store.create_draft("tenant-a", self.contract(), "alice")
        self.assertIsNone(contracts_store.get_latest("tenant-b", "atjm-contract-001"))
        self.assertEqual(contracts_store.list_latest("tenant-b"), [])

    def test_approval_requires_different_actor_and_creates_new_version(self):
        contracts_store.create_draft("tenant-a", self.contract(), "alice")
        with self.assertRaises(PermissionError):
            contracts_store.approve_latest("tenant-a", "atjm-contract-001", "alice")
        approved = contracts_store.approve_latest("tenant-a", "atjm-contract-001", "bob")
        self.assertEqual(approved["version"], 2)
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["approved_by"], "bob")

    def test_only_latest_draft_can_be_approved(self):
        contracts_store.create_draft("tenant-a", self.contract(), "alice")
        contracts_store.approve_latest("tenant-a", "atjm-contract-001", "bob")
        with self.assertRaises(ValueError):
            contracts_store.approve_latest("tenant-a", "atjm-contract-001", "carol")


if __name__ == "__main__":
    unittest.main()
