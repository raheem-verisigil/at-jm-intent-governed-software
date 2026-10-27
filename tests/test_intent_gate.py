import unittest

from integrations.github.at_jm_gate import CONTRACT_PATH, evaluate_changes, validate_contract


def contract(**policy_overrides):
    policy = {
        "prohibited_paths": ["secrets/**", "infra/production/**"],
        "max_changed_files": 12,
    }
    policy.update(policy_overrides)
    return {
        "schema_version": "1.0",
        "contract_id": "atjm-test-contract",
        "status": "approved",
        "intent": {"statement": "Make a bounded application change without changing production infrastructure."},
        "policy": policy,
    }


class IntentGateTests(unittest.TestCase):
    def test_valid_approved_contract(self):
        self.assertEqual(validate_contract(contract()), [])

    def test_draft_contract_fails_closed(self):
        candidate = contract()
        candidate["status"] = "draft"
        self.assertTrue(any("approved" in error for error in validate_contract(candidate)))

    def test_missing_contract_sections_fail_closed(self):
        self.assertTrue(validate_contract({}))

    def test_prohibited_path_is_blocked(self):
        report = evaluate_changes(contract(), ["app/main.py", "secrets/prod.env"])
        self.assertFalse(report["passed"])
        self.assertIn("secrets/prod.env", report["prohibited_path_matches"])

    def test_file_limit_is_enforced(self):
        report = evaluate_changes(contract(max_changed_files=1), ["a.py", "b.py"])
        self.assertFalse(report["passed"])
        self.assertTrue(any("exceeds" in error for error in report["errors"]))

    def test_contract_cannot_be_changed_in_same_pr(self):
        report = evaluate_changes(contract(), [CONTRACT_PATH, "app/main.py"])
        self.assertFalse(report["passed"])
        self.assertTrue(any("cannot be changed" in error for error in report["errors"]))

    def test_safe_bounded_change_passes(self):
        report = evaluate_changes(contract(), ["app/main.py", "tests/test_main.py"])
        self.assertTrue(report["passed"])
        self.assertEqual(report["changed_files"], 2)

    def test_bad_max_file_limit_fails_contract_validation(self):
        candidate = contract(max_changed_files=True)
        self.assertTrue(any("max_changed_files" in error for error in validate_contract(candidate)))


if __name__ == "__main__":
    unittest.main()
