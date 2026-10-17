
"""IFC Digital - HTTP project authorization tests.

Tests real local HTTP requests with simulated
authentication and project permissions.
No production accounts or database required.
"""

import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import MagicMock, patch

import server


class ProjectPermissionsHTTPTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            server.Handler
        )
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(
            target=cls.httpd.serve_forever,
            daemon=True
        )
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def request(self, path, token=None):
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.port,
            timeout=5
        )

        headers = {}
        if token is not None:
            headers["Authorization"] = (
                "Bearer " + token
            )

        try:
            connection.request(
                "GET",
                path,
                headers=headers
            )
            response = connection.getresponse()
            status = response.status
            data = json.loads(
                response.read().decode("utf-8")
            )
            return status, data
        finally:
            connection.close()

    def test_missing_login_returns_401(self):
        status, data = self.request(
            "/api/v1/test-project"
        )
        self.assertEqual(status, 401)
        self.assertEqual(
            data["message"],
            "Unauthorized"
        )

    def test_invalid_session_returns_401(self):
        auth = MagicMock()
        auth.authenticate.return_value = None

        with patch.object(
            server,
            "authentication_service",
            return_value=auth
        ):
            status, data = self.request(
                "/api/v1/test-project",
                "invalid-session"
            )

        self.assertEqual(status, 401)
        self.assertEqual(
            data["message"],
            "Unauthorized"
        )

    def test_valid_user_without_access_403(self):
        auth = MagicMock()
        auth.authenticate.return_value = {
            "id": 42
        }

        permissions = MagicMock()
        permissions.can_access.return_value = False

        with patch.object(
            server,
            "authentication_service",
            return_value=auth
        ), patch.object(
            server,
            "ProjectPermissionService",
            return_value=permissions
        ):
            status, data = self.request(
                "/api/v1/test-project",
                "valid-session"
            )

        self.assertEqual(status, 403)
        self.assertEqual(
            data["message"],
            "Forbidden"
        )

        permissions.can_access.assert_called_once_with(
            42,
            "PRJ-0041",
            "projects.read"
        )

    def test_valid_user_with_access_200(self):
        auth = MagicMock()
        auth.authenticate.return_value = {
            "id": 42
        }

        permissions = MagicMock()
        permissions.can_access.return_value = True

        with patch.object(
            server,
            "authentication_service",
            return_value=auth
        ), patch.object(
            server,
            "ProjectPermissionService",
            return_value=permissions
        ):
            status, data = self.request(
                "/api/v1/test-project",
                "valid-session"
            )

        self.assertEqual(status, 200)
        self.assertEqual(
            data["project_id"],
            "PRJ-0041"
        )
        self.assertTrue(data["test_data"])

        permissions.can_access.assert_called_once_with(
            42,
            "PRJ-0041",
            "projects.read"
        )

    def test_unknown_endpoint_returns_404(self):
        status, data = self.request(
            "/api/v1/unknown"
        )
        self.assertEqual(status, 404)
        self.assertEqual(
            data["error"],
            "not_found"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
