
"""IFC Digital - Sprint 342 - HTTP integration tests.

Real HTTP requests to a temporary local test server.
Authentication and database services are mocked.
No production systems or customer data are accessed.
"""

import json
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import urlopen

sys.path.insert(0, str(Path(__file__).resolve().parent))

import server_staging_v3 as v3


class HTTPIntegrationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), v3.Handler
        )
        cls.server.daemon_threads = True
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(
            target=cls.server.serve_forever,
            daemon=True,
        )
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        self.auth_patch = patch.object(
            v3.Handler, "authorize_user",
            return_value={"id": 42},
        )
        self.service_patch = patch.object(
            v3, "ProjectPermissionService"
        )
        self.factory_patch = patch.object(
            v3.server_staging_v2.server,
            "authentication_service",
        )

        self.mock_authorize = self.auth_patch.start()
        self.mock_service = self.service_patch.start()
        self.mock_factory = self.factory_patch.start()

        self.mock_service.return_value.check.return_value = (
            MagicMock(allowed=True)
        )

        self.addCleanup(self.auth_patch.stop)
        self.addCleanup(self.service_patch.stop)
        self.addCleanup(self.factory_patch.stop)

    def request(self, params=None, raw_query=None):
        path = v3.CHECK_PATH

        if raw_query is not None:
            path += "?" + raw_query
        elif params is not None:
            path += "?" + urlencode(params)

        url = f"http://127.0.0.1:{self.port}{path}"

        try:
            with urlopen(url, timeout=5) as response:
                return (
                    response.status,
                    json.loads(response.read()),
                )
        except HTTPError as error:
            return (
                error.code,
                json.loads(error.read()),
            )

    def valid_params(self):
        return {
            "project_id": "PRJ-TEST-001",
            "permission": "projects.read",
        }

    def test_01_allowed_access_returns_200(self):
        status, body = self.request(self.valid_params())

        self.assertEqual(status, 200)
        self.assertTrue(body["allowed"])
        self.assertEqual(body["status"], "ok")

        self.mock_service.return_value.check.assert_called_with(
            42, "PRJ-TEST-001", "projects.read"
        )

    def test_02_denied_access_returns_403(self):
        self.mock_service.return_value.check.return_value = (
            MagicMock(allowed=False)
        )

        status, body = self.request(self.valid_params())

        self.assertEqual(status, 403)
        self.assertEqual(body["message"], "Forbidden")

    def test_03_missing_session_is_rejected(self):
        self.mock_authorize.return_value = None

        # Simulate the HTTP response normally sent
        # by the existing authentication handler.
        def deny(handler):
            handler.send_json(
                401,
                {
                    "status": "error",
                    "message": "Unauthorized",
                },
            )
            return None

        self.mock_authorize.side_effect = deny

        status, body = self.request(self.valid_params())

        self.assertEqual(status, 401)
        self.assertEqual(body["message"], "Unauthorized")
        self.mock_service.assert_not_called()

    def test_04_invalid_permission_returns_400(self):
        params = self.valid_params()
        params["permission"] = "invalid.permission"

        status, body = self.request(params)

        self.assertEqual(status, 400)
        self.assertEqual(
            body["message"], "Invalid parameters"
        )

    def test_05_missing_project_returns_400(self):
        status, body = self.request({
            "permission": "projects.read"
        })

        self.assertEqual(status, 400)
        self.assertEqual(
            body["message"], "Invalid parameters"
        )

    def test_06_duplicate_parameters_returns_400(self):
        status, body = self.request(
            raw_query=(
                "project_id=A&project_id=B"
                "&permission=projects.read"
            )
        )

        self.assertEqual(status, 400)
        self.assertEqual(
            body["message"], "Invalid parameters"
        )

    def test_07_service_failure_returns_503(self):
        self.mock_service.return_value.check.side_effect = (
            RuntimeError("Simulated database failure")
        )

        with patch.object(v3.logging, "exception"):
            status, body = self.request(
                self.valid_params()
            )

        self.assertEqual(status, 503)
        self.assertEqual(
            body["message"], "Service unavailable"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
