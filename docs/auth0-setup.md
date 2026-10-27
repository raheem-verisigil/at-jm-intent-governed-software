# Configure Auth0 for AT-JM

This repository includes the Auth0 login flow and dashboard code. **It is not live until you create an Auth0 tenant/application/API and add the settings to Railway.** Do not commit client secrets or tokens.

## 1. Create Auth0 account and application

1. Create/sign in to your Auth0 account at https://auth0.com/.
2. Create a tenant. Copy the tenant domain, for example `your-tenant.us.auth0.com` (do not include `https://`).
3. Create an application of type **Regular Web Application**.
4. In its settings, add these exact URLs (replace the host with the current Railway domain):
   - Allowed Callback URLs: `https://at-jm-runtime-production.up.railway.app/auth/callback`
   - Allowed Logout URLs: `https://at-jm-runtime-production.up.railway.app/`
   - Allowed Web Origins: `https://at-jm-runtime-production.up.railway.app`
5. Copy the Client ID and Client Secret into Railway variables only.

## 2. Create an Auth0 API

1. Create an API. Identifier/audience: `https://api.at-jm.ai` (this is an identifier, not a URL we need to host).
2. Choose RS256 signing.
3. Enable RBAC and add permissions including `atjm:contracts:approve` for designated approvers only. Enable adding permissions to the access token if using the Auth0 permissions claim.
4. Ensure tokens issued for this API contain a tenant claim controlled by the administrator, not user-editable input.

## 3. Add a Post-Login Action for tenant and permissions claims

Create a **Post Login** Action and deploy it. Assign a tenant identifier to each user using Auth0 user `app_metadata.atjm_tenant_id`; only trusted administrators should set this field. Do not use user_metadata or a value sent from the browser.

```javascript
exports.onExecutePostLogin = async (event, api) => {
  const tenantId = event.user.app_metadata?.atjm_tenant_id;
  if (!tenantId || typeof tenantId !== "string") {
    api.access.deny("Your AT-JM tenant has not been provisioned.");
    return;
  }
  // The dashboard session is established from the ID token; protected API
  // operations continue to require a separately validated API access token.
  api.idToken.setCustomClaim("https://at-jm.ai/tenant_id", tenantId);
  api.accessToken.setCustomClaim("https://at-jm.ai/tenant_id", tenantId);
};
```

The API should also issue the `permissions` claim using Auth0 RBAC. If your tenant's token format differs, update the documented claim mapping before enabling access. The login flow requests an ID token only and does not request this API as an audience; protected API bearer-token calls still require the API audience and the configured tenant/permission claims.

## 4. Add variables in Railway

Open the Railway project `AT-JM-Promise-Runtime`, service `at-jm-runtime`, production environment, then Variables. Add these values there; never put secrets in GitHub, `Dockerfile`, or the public frontend.

| Variable | Value |
|---|---|
| `ATJM_AUTH0_DOMAIN` | Your Auth0 tenant hostname only, e.g. `your-tenant.us.auth0.com` |
| `ATJM_AUTH0_CLIENT_ID` | Auth0 Regular Web Application Client ID |
| `ATJM_AUTH0_CLIENT_SECRET` | Auth0 Regular Web Application Client Secret |
| `ATJM_PUBLIC_ORIGIN` | `https://at-jm-runtime-production.up.railway.app` |
| `ATJM_OIDC_ISSUER` | `https://YOUR_AUTH0_DOMAIN/` including trailing slash |
| `ATJM_OIDC_AUDIENCE` | `https://api.at-jm.ai` (exact API identifier) |
| `ATJM_OIDC_JWKS_URL` | `https://YOUR_AUTH0_DOMAIN/.well-known/jwks.json` |
| `ATJM_TENANT_CLAIM` | `https://at-jm.ai/tenant_id` |
| `ATJM_ROLE_CLAIM` | `permissions` |
| `ATJM_APPROVAL_PERMISSION` | `atjm:contracts:approve` |

Replace `YOUR_AUTH0_DOMAIN` with the same Auth0 hostname in both URLs. Keep the issuer's trailing slash. Use Railway's variable editor so the secret is stored in the deployment environment, not source control. Variables trigger a redeploy.

## 5. Persist session storage

The app expects `ATJM_DATA_DIR=/data`. Confirm the Railway service has a persistent volume mounted at `/data`; otherwise sessions may be lost during redeploy/restart. SQLite and the in-memory PKCE transaction cache are for a single replica. Keep one replica for this initial pilot; move sessions, login transactions, and contract storage to a shared managed database before horizontal scaling.

## 6. Verify before inviting a pilot user

1. Open `/api/health` and confirm `oidc_management_configured: true`.
2. Open `/login`; it should redirect to Auth0 Universal Login.
3. Sign in with a test account whose `app_metadata.atjm_tenant_id` has been assigned by an administrator.
4. Confirm the browser returns to `/dashboard`, shows the signed-in account, and lists only that tenant's contracts.
5. Create a draft and verify it appears with a content digest.
6. Try a second tenant and confirm it cannot read the first tenant's contract.
7. Test missing/expired/wrong-audience tokens, missing tenant claims, self-approval, and users without approval permission.
8. Confirm logout invalidates the AT-JM session cookie and session record.

## Current boundaries

This is an initial Auth0 integration. It has not had an independent security audit. It does not include a tenant provisioning interface, invitation flow, password policy configuration, account recovery, organization administration, or approval UI. The dashboard can create and inspect drafts; independent approvals currently use the protected API. Do not call it production-ready until the above tests and a security review pass.
