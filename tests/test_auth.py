import os
import unittest
from unittest.mock import patch

import auth


class AuthConfigurationTests(unittest.TestCase):
    def test_missing_oidc_configuration_fails_closed(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(auth.AuthUnavailable):
                auth.verify_bearer_token("Bearer example-token")

    def test_non_https_oidc_urls_are_rejected(self):
        with patch.dict(os.environ, {
            "ATJM_OIDC_ISSUER": "http://issuer.invalid/",
            "ATJM_OIDC_AUDIENCE": "at-jm-api",
            "ATJM_OIDC_JWKS_URL": "http://issuer.invalid/jwks",
        }, clear=True):
            with self.assertRaises(auth.AuthUnavailable):
                auth.verify_bearer_token("Bearer example-token")


if __name__ == "__main__":
    unittest.main()
