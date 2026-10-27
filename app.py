import json, os, re, time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
ROOT=Path(__file__).resolve().parent
ACTIONS={"read_source","edit_candidate_code","run_tests_in_sandbox","deploy","delete","external","credentials","charge_real_customer","modify_production_credentials"}
ENVIRONMENTS={"development","staging","production"}; RISKS={"low","medium","high"}; EVIDENCE={"passed","failed","missing","conflicting"}; RULES={"standard","noExternal","noProd"}
DEMO={"contract_version":"0.1","contract_id":"atjm-demo-001","status":"draft","goal":{"statement":"Add subscription billing without duplicate charges","acceptance_criteria":[{"id":"AC-001","description":"Repeated billing events do not create duplicate charges","verification":"automated_test","required":True}]},"invariants":[{"id":"INV-001","rule":"A billing event must not create duplicate charges","severity":"critical"}],"prohibitions":[{"id":"PRO-001","rule":"Do not access production payment credentials from development","severity":"critical"}],"authority":{"allowed_actions":["read_source","edit_candidate_code","run_tests_in_sandbox"],"denied_actions":["charge_real_customer","modify_production_credentials"],"human_approval_required_for":["production_deployment","real_payment_execution"]},"verification":{"required_checks":["acceptance_tests","invariant_tests","security_checks","regression_tests"]},"evidence":{"record_contract_version":True,"record_source_changes":True,"record_tool_actions":True,"record_test_results":True},"change_control":{"material_change_requires_revalidation":True,"contract_amendment_requires_authorization":True}}
def validate_contract(c):
 if not isinstance(c,dict): return {"valid":False,"errors":["Contract must be a JSON object."]}
 required={"contract_version","contract_id","status","goal","invariants","prohibitions","authority","verification","evidence","change_control"}; errors=[]
 if required-c.keys(): errors.append("Missing fields: "+", ".join(sorted(required-c.keys())))
 if c.get("contract_version")!="0.1": errors.append("contract_version must be '0.1'.")
 if not isinstance(c.get("contract_id"),str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}",c.get("contract_id","")): errors.append("contract_id format is invalid.")
 if c.get("status") not in {"draft","approved","retired"}: errors.append("status must be draft, approved or retired.")
 g=c.get("goal")
 if not isinstance(g,dict) or not isinstance(g.get("statement"),str) or not g["statement"].strip(): errors.append("goal.statement must be non-empty.")
 if not isinstance(g,dict) or not isinstance(g.get("acceptance_criteria"),list) or not g["acceptance_criteria"]: errors.append("goal.acceptance_criteria must be a non-empty array.")
 for k in ("invariants","prohibitions"):
  if not isinstance(c.get(k),list): errors.append(k+" must be an array.")
 for k in ("authority","verification","evidence","change_control"):
  if not isinstance(c.get(k),dict): errors.append(k+" must be an object.")
 if errors:return {"valid":False,"errors":errors,"validator_version":"0.1.0"}
 return {"valid":True,"contract_id":c["contract_id"],"contract_version":"0.1","status":c["status"],"acceptance_criteria_count":len(g["acceptance_criteria"]),"validator_version":"0.1.0","warnings":["Draft contracts are not release authority.","Approval status is not authenticated in this prototype."]}
def result(decision,reason,p,next_steps):
 return {"schema_version":"0.1","decision_id":"dec-"+str(int(time.time()*1000)),"timestamp":datetime.now(timezone.utc).isoformat(),"decision":decision,"reason":reason,"inputs":p,"next_steps":next_steps,"execution_performed":False,"limitations":["No identity verification","No external system access","No code execution","Not production authorization"]}
def evaluate(p):
 if not isinstance(p,dict):return result("ERROR","Request must be a JSON object.",p,["Send structured JSON."])
 req={"action","environment","risk_level","evidence_status","contract_rule"}
 if req-p.keys():return result("INDETERMINATE","Missing inputs: "+", ".join(sorted(req-p.keys())),p,["Provide every required input."])
 if p["action"] not in ACTIONS or p["environment"] not in ENVIRONMENTS or p["risk_level"] not in RISKS or p["evidence_status"] not in EVIDENCE or p["contract_rule"] not in RULES:return result("INDETERMINATE","Unknown policy input value.",p,["Use supported values."])
 a,e,r,v,rule=(p[k] for k in ("action","environment","risk_level","evidence_status","contract_rule"))
 if v in {"failed","conflicting"}:return result("DENY","Evidence failed or is contradictory.",p,["Resolve evidence issues and rerun checks."])
 if a in {"delete","credentials","charge_real_customer","modify_production_credentials"}:return result("DENY","Prototype hard-prohibition policy blocks this action.",p,["Use a separately designed authorized workflow."])
 if rule=="noExternal" and a=="external":return result("DENY","Contract rule prohibits external data transfer.",p,["Keep data within the approved boundary."])
 if rule=="noProd" and e=="production" and a in {"deploy","edit_candidate_code","external"}:return result("DENY","Contract rule prohibits mutation in production.",p,["Use non-production or amend the contract through authorized review."])
 if v=="missing":return result("INDETERMINATE","Required evidence is missing.",p,["Collect evidence or escalate."])
 if a=="deploy" or e=="production" or r=="high" or a=="external":return result("REQUIRE_APPROVAL","Sensitive or high-impact action requires human review.",p,["Review scope, evidence, contract version and rollback plan."])
 if a not in {"read_source","edit_candidate_code","run_tests_in_sandbox"}:return result("DENY","Action is not in the prototype permitted set.",p,["Declare and review capability before requesting it."])
 return result("ALLOW","Structured request passes prototype rules.",p,["Policy result only; no action was executed."])
class Handler(BaseHTTPRequestHandler):
 def send_json(self,status,obj):
  b=json.dumps(obj,ensure_ascii=False,indent=2).encode();self.send_response(status);self.send_header("Content-Type","application/json; charset=utf-8");self.send_header("Content-Length",str(len(b)));self.send_header("X-Content-Type-Options","nosniff");self.send_header("Cache-Control","no-store");self.end_headers();self.wfile.write(b)
 def do_GET(self):
  if self.path=="/api/health":return self.send_json(200,{"status":"ok","service":"AT-JM Promise Runtime","version":"0.1.0","capabilities":["contract_validation","bounded_policy_evaluation"],"execution_performed":False})
  if self.path=="/api/demo-contract":return self.send_json(200,DEMO)
  if self.path in {"/","/index.html"}:
   try:
    b=(ROOT/"index.html").read_bytes();self.send_response(200);self.send_header("Content-Type","text/html; charset=utf-8");self.send_header("Content-Length",str(len(b)));self.send_header("X-Content-Type-Options","nosniff");self.end_headers();self.wfile.write(b)
   except OSError:self.send_json(500,{"error":"Website file unavailable."})
   return
  self.send_json(404,{"error":"Not found"})
 def do_POST(self):
  if self.path not in {"/api/contract/validate","/api/policy/evaluate"}:return self.send_json(404,{"error":"Not found"})
  try:
   n=int(self.headers.get("Content-Length","0"))
   if n<1 or n>1000000:return self.send_json(413 if n>1000000 else 400,{"error":"Body must be between 1 byte and 1 MB."})
   p=json.loads(self.rfile.read(n))
  except (ValueError,json.JSONDecodeError):return self.send_json(400,{"error":"Body must be valid JSON."})
  if self.path=="/api/contract/validate":
   r=validate_contract(p);return self.send_json(200 if r["valid"] else 422,r)
  return self.send_json(200,evaluate(p))
 def log_message(self,fmt,*args):print("%s %s"%(self.log_date_time_string(),fmt%args))
if __name__=="__main__":ThreadingHTTPServer(("0.0.0.0",int(os.environ.get("PORT","8080"))),Handler).serve_forever()
