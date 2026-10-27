import json
import os
import tempfile
import unittest
from unittest.mock import patch

import audit_ledger


class AuditLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"ATJM_DATA_DIR": self.tempdir.name})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.tempdir.cleanup()

    def decision(self, decision_id, verdict="ALLOW"):
        return {
            "decision_id": decision_id,
            "timestamp": "2026-10-27T00:00:00+00:00",
            "decision": verdict,
            "reason": "test reason",
            "schema_version": "0.1",
        }

    def test_append_and_verify_empty_chain(self):
        self.assertTrue(audit_ledger.verify_chain()["valid"])
        meta = audit_ledger.append_decision(self.decision("dec-test-001"), {"action": "read_source"})
        self.assertEqual(meta["sequence"], 1)
        report = audit_ledger.verify_chain()
        self.assertTrue(report["valid"])
        self.assertEqual(report["event_count"], 1)

    def test_input_payload_is_not_stored_raw(self):
        secret_like_value = "private-test-value-do-not-store"
        audit_ledger.append_decision(self.decision("dec-test-002"), {"value": secret_like_value})
        database = audit_ledger._db_path()
        import sqlite3
        with sqlite3.connect(database) as connection:
            stored = connection.execute("SELECT event_json FROM audit_events").fetchone()[0]
        self.assertNotIn(secret_like_value, stored)
        self.assertIn("input_sha256", stored)

    def test_modified_event_is_detected(self):
        audit_ledger.append_decision(self.decision("dec-test-003"), {"action": "read_source"})
        import sqlite3
        with sqlite3.connect(audit_ledger._db_path()) as connection:
            event = json.loads(connection.execute("SELECT event_json FROM audit_events").fetchone()[0])
            event["decision"] = "DENY"
            connection.execute("UPDATE audit_events SET event_json = ? WHERE sequence = 1", (json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False),))
        report = audit_ledger.verify_chain()
        self.assertFalse(report["valid"])
        self.assertEqual(report["failed_sequence"], 1)

    def test_duplicate_event_id_is_rejected(self):
        audit_ledger.append_decision(self.decision("dec-test-004"), {"action": "read_source"})
        with self.assertRaises(Exception):
            audit_ledger.append_decision(self.decision("dec-test-004"), {"action": "read_source"})
        self.assertEqual(audit_ledger.verify_chain()["event_count"], 1)


if __name__ == "__main__":
    unittest.main()
