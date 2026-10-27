import unittest
from app import DEMO,evaluate,validate_contract
class RuntimeTests(unittest.TestCase):
 def payload(self,**kw):
  p={"action":"read_source","environment":"development","risk_level":"low","evidence_status":"passed","contract_rule":"standard"};p.update(kw);return p
 def test_demo_contract_validates(self):self.assertTrue(validate_contract(DEMO)["valid"])
 def test_empty_contract_rejected(self):self.assertFalse(validate_contract({})["valid"])
 def test_safe_dev_action_allowed(self):self.assertEqual(evaluate(self.payload())["decision"],"ALLOW")
 def test_missing_evidence_indeterminate(self):self.assertEqual(evaluate(self.payload(evidence_status="missing"))["decision"],"INDETERMINATE")
 def test_failed_evidence_denied(self):self.assertEqual(evaluate(self.payload(evidence_status="failed"))["decision"],"DENY")
 def test_conflicting_evidence_denied(self):self.assertEqual(evaluate(self.payload(evidence_status="conflicting"))["decision"],"DENY")
 def test_customer_charge_denied(self):self.assertEqual(evaluate(self.payload(action="charge_real_customer"))["decision"],"DENY")
 def test_production_requires_approval(self):self.assertEqual(evaluate(self.payload(environment="production"))["decision"],"REQUIRE_APPROVAL")
 def test_high_risk_requires_approval(self):self.assertEqual(evaluate(self.payload(risk_level="high"))["decision"],"REQUIRE_APPROVAL")
 def test_deploy_requires_approval(self):self.assertEqual(evaluate(self.payload(action="deploy"))["decision"],"REQUIRE_APPROVAL")
 def test_policy_does_not_execute(self):self.assertFalse(evaluate(self.payload())["execution_performed"])
 def test_unknown_enum_indeterminate(self):self.assertEqual(evaluate(self.payload(action="unknown"))["decision"],"INDETERMINATE")
if __name__=="__main__":unittest.main()
