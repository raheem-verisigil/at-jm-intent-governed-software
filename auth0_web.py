"""Auth0 Authorization Code + PKCE login and opaque server-side sessions."""
from __future__ import annotations
import hashlib,json,os,secrets,sqlite3,time
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.error import HTTPError,URLError
from urllib.parse import urlencode
from urllib.request import Request,urlopen
import auth

class LoginNotConfigured(Exception): pass
class LoginRejected(Exception): pass
_flows: dict[str,dict]={}

def _config():
    domain=os.environ.get("ATJM_AUTH0_DOMAIN","").strip().rstrip("/")
    client=os.environ.get("ATJM_AUTH0_CLIENT_ID","").strip()
    secret=os.environ.get("ATJM_AUTH0_CLIENT_SECRET","").strip()
    audience=os.environ.get("ATJM_OIDC_AUDIENCE","").strip()
    origin=os.environ.get("ATJM_PUBLIC_ORIGIN","").strip().rstrip("/")
    if not domain or "://" in domain or "/" in domain or " " in domain: raise LoginNotConfigured("Set ATJM_AUTH0_DOMAIN to your Auth0 tenant hostname.")
    if not client or not secret: raise LoginNotConfigured("Auth0 client ID and secret are required.")
    if not origin.startswith("https://"): raise LoginNotConfigured("ATJM_PUBLIC_ORIGIN must be the public HTTPS origin.")
    issuer=f"https://{domain}/"
    if os.environ.get("ATJM_OIDC_ISSUER",issuer).strip()!=issuer: raise LoginNotConfigured("ATJM_OIDC_ISSUER must match Auth0 domain.")
    if os.environ.get("ATJM_OIDC_JWKS_URL",issuer+".well-known/jwks.json").strip()!=issuer+".well-known/jwks.json": raise LoginNotConfigured("ATJM_OIDC_JWKS_URL must match Auth0 domain.")
    return {"domain":domain,"client":client,"secret":secret,"audience":audience,"origin":origin,"issuer":issuer}

def _identity_from_id_claims(claims):
    subject=claims.get("sub")
    if not isinstance(subject,str) or not subject.strip(): raise LoginRejected("ID token subject is missing.")
    tenant_claim=os.environ.get("ATJM_TENANT_CLAIM","https://at-jm.ai/tenant_id")
    tenant=claims.get(tenant_claim)
    if not isinstance(tenant,str) or not tenant.strip() or len(tenant)>256:
        raise LoginRejected("ID token does not include the configured tenant claim.")
    role_claim=os.environ.get("ATJM_ROLE_CLAIM","permissions")
    roles=claims.get(role_claim,[])
    if isinstance(roles,str): roles=[roles]
    if not isinstance(roles,list) or any(not isinstance(x,str) for x in roles):
        raise LoginRejected("ID token permissions claim has invalid format.")
    return {"subject":subject,"tenant_id":tenant,"roles":roles,"claims":claims}


def _connect():
    directory=Path(os.environ.get("ATJM_DATA_DIR","data")).expanduser()
    directory.mkdir(parents=True,exist_ok=True)
    db=sqlite3.connect(str(directory/"atjm-sessions.sqlite3"),timeout=10)
    db.execute("PRAGMA busy_timeout=10000")
    db.execute("""CREATE TABLE IF NOT EXISTS web_sessions_v2(session_hash TEXT PRIMARY KEY,id_token TEXT NOT NULL,csrf_token TEXT NOT NULL,expires_at INTEGER NOT NULL,created_at INTEGER NOT NULL)""")
    return db

def begin_login():
    c=_config(); state=secrets.token_urlsafe(32); nonce=secrets.token_urlsafe(32)
    verifier=secrets.token_urlsafe(64)
    import base64
    challenge=base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    now=int(time.time()); _flows[state]={"nonce":nonce,"verifier":verifier,"created":now}
    for k,v in list(_flows.items()):
        if now-v["created"]>600: _flows.pop(k,None)
    q=urlencode({"response_type":"code","client_id":c["client"],"redirect_uri":c["origin"]+"/auth/callback","scope":"openid profile email","state":state,"nonce":nonce,"code_challenge":challenge,"code_challenge_method":"S256"})
    return f"https://{c['domain']}/authorize?{q}"

def finish_login(code,state):
    c=_config(); flow=_flows.pop(state,None)
    if not flow or int(time.time())-flow["created"]>600: raise LoginRejected("Login state expired or invalid.")
    data=urlencode({"grant_type":"authorization_code","client_id":c["client"],"client_secret":c["secret"],"code":code,"redirect_uri":c["origin"]+"/auth/callback","code_verifier":flow["verifier"]}).encode()
    req=Request(f"https://{c['domain']}/oauth/token",data=data,headers={"Content-Type":"application/x-www-form-urlencoded","Accept":"application/json"},method="POST")
    try:
        with urlopen(req,timeout=8) as response: tokens=json.loads(response.read(65536))
    except (HTTPError,URLError,TimeoutError,ValueError) as exc: raise LoginRejected("Auth0 token exchange failed.") from exc
    id_token=tokens.get("id_token")
    if not isinstance(id_token,str): raise LoginRejected("Auth0 did not return an ID token.")
    idclaims=auth.verify_signed_jwt(id_token,c["client"],c["issuer"])
    import hmac
    if not hmac.compare_digest(str(idclaims.get("nonce","")),flow["nonce"]): raise LoginRejected("ID token nonce validation failed.")
    identity=_identity_from_id_claims(idclaims)
    expires=int(idclaims["exp"]); now=int(time.time())
    if expires<=now: raise LoginRejected("Auth0 returned an expired access token.")
    sid=secrets.token_urlsafe(48); csrf=secrets.token_urlsafe(32); digest=hashlib.sha256(sid.encode()).hexdigest()
    db=_connect()
    try:
        db.execute("DELETE FROM web_sessions_v2 WHERE expires_at<=?",(now,))
        db.execute("INSERT INTO web_sessions_v2 VALUES(?,?,?,?,?)",(digest,id_token,csrf,expires,now)); db.commit()
    finally: db.close()
    return sid,csrf,expires

def get_session(cookie_header):
    if not cookie_header:return None
    cookie=SimpleCookie()
    try: cookie.load(cookie_header)
    except Exception:return None
    m=cookie.get("atjm_session")
    if not m or not m.value or len(m.value)>256:return None
    digest=hashlib.sha256(m.value.encode()).hexdigest(); db=_connect()
    try: row=db.execute("SELECT id_token,csrf_token,expires_at FROM web_sessions_v2 WHERE session_hash=?",(digest,)).fetchone()
    finally: db.close()
    if not row or row[2]<=int(time.time()):return None
    try:
        claims=auth.verify_signed_jwt(row[0],_config()["client"],_config()["issuer"])
        identity=_identity_from_id_claims(claims)
    except (LoginNotConfigured, auth.AuthUnavailable, auth.AuthRejected):
        return None
    return {"identity":identity,"id_token":row[0],"csrf_token":row[1],"expires_at":row[2],"session_hash":digest}

def logout(cookie_header):
    session=get_session(cookie_header)
    if not session:return
    db=_connect()
    try: db.execute("DELETE FROM web_sessions_v2 WHERE session_hash=?",(session["session_hash"],)); db.commit()
    finally: db.close()

def session_cookie(sid,expires):
    return f"atjm_session={sid}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max(0,expires-int(time.time()))}"
def clear_cookie():
    return "atjm_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"
def logout_url():
    c=_config()
    return f"https://{c['domain']}/v2/logout?{urlencode({'client_id':c['client'],'returnTo':c['origin']+'/'})}"
