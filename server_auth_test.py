
"""IFC Digital - Webserver authentication tests.

Sprint P1.2.4-B.4
Tests existing security and defines requirements
for the upcoming personal user authentication.
"""

import inspect
import unittest

import server


class ExistingServerSecurityTests(unittest.TestCase):

    def test_api_token_validation_exists(self):
        self.assertTrue(
            callable(getattr(server.Handler, "authorized", None))
        )

    def test_api_token_is_required(self):
        source = inspect.getsource(
            server.Handler.authorized
        )
        self.assertIn("compare_digest", source)
        self.assertIn("API_TOKEN", source)

    def test_request_size_limit_exists(self):
        self.assertEqual(
            server.MAX_BODY_BYTES,
            1024 * 1024
        )

    def test_subcontractor_validation(self):
        valid = {
            "company_name": "IFC Test GmbH",
            "contact_name": "Max Muster",
            "contact_email": "test@example.test"
        }

        result = server.validate_subcontractor(valid)
        self.assertIsNotNone(result)
        self.assertEqual(
            result["company_name"],
            "IFC Test GmbH"
        )

    def test_invalid_subcontractor_rejected(self):
        self.assertIsNone(
            server.validate_subcontractor({
                "company_name": ""
            })
        )


class PlannedAuthenticationTests(unittest.TestCase):
    """Requirements for the next server integration."""

    def test_login_endpoint_required(self):
        self.assertTrue(
            callable(
                getattr(
                    server.Handler,
                    "handle_user_login",
                    None
                )
            ),
            "Personal login endpoint is not implemented"
        )

    def test_user_authorization_required(self):
        self.assertTrue(
            callable(
                getattr(
                    server.Handler,
                    "authorize_user",
                    None
                )
            ),
            "User authorization is not implemented"
        )

    def test_project_authorization_required(self):
        self.assertTrue(
            callable(
                getattr(
                    server.Handler,
                    "authorize_project",
                    None
                )
            ),
            "Project authorization is not implemented"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
