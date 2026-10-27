import os
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import auth0_web


class Auth0WebTests(unittest.TestCase):
    def test_login_fails_closed_without_configuration(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(auth0_web.LoginNotConfigured):
                auth0_web.begin_login()

    def test_login_url_uses_pkce_state_nonce_and_https(self):
        env = {
            "ATJM_AUTH0_DOMAIN": "example.us.auth0.com",
            "ATJM_AUTH0_CLIENT_ID": "client-id",
            "ATJM_AUTH0_CLIENT_SECRET": "test-secret",
            "ATJM_OIDC_AUDIENCE": "https://api.at-jm.ai",
            "ATJM_PUBLIC_ORIGIN": "https://at-jm-runtime-production.up.railway.app",
        }
        with patch.dict(os.environ, env, clear=True):
            url = auth0_web.begin_login()
        parsed = urlsplit(url)
        params = parse_qs(parsed.query)
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(parsed.netloc, "example.us.auth0.com")
        self.assertEqual(parsed.path, "/authorize")
        self.assertEqual(params["response_type"], ["code"])
        self.assertEqual(params["code_challenge_method"], ["S256"])
        self.assertTrue(params["code_challenge"][0])
        self.assertTrue(params["state"][0])
        self.assertTrue(params["nonce"][0])
        self.assertNotIn("test-secret", url)

    def test_session_cookie_has_secure_httponly_samesite_flags(self):
        header = auth0_web.session_cookie("opaque-id", 2000)
        self.assertIn("HttpOnly", header)
        self.assertIn("Secure", header)
        self.assertIn("SameSite=Lax", header)


if __name__ == "__main__":
    unittest.main()
