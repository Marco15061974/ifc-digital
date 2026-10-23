
"""IFC Digital - Staging Server HTTP Tests.

Tests project assignment HTTP routes using a local
test server and mocked authentication and services.

No production database or real users are required.
"""

import http.client
import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch
from urllib.parse import urlencode

import server_staging_v2 as staging
from project_assignments import AssignmentError


class StagingHTTPTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0),
            staging.Handler,
        )
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(
            target=cls.httpd.serve_forever,
            daemon=True,
        )
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def setUp(self):
        self.user = {"id": 1}
        self.auth_patch = patch.object(
            staging.Handler,
            "authorize_user",
            return_value=self.user,
        )
        self.auth_patch.start()

        self.api_patch = patch.object(
            staging,
            "ProjectAssignmentAPI",
        )
        self.api_class = self.api_patch.start()
        self.api = self.api_class.return_value

    def tearDown(self):
        self.api_patch.stop()
        self.auth_patch.stop()

    def request(self, method, path, payload=None):
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            self.port,
            timeout=5,
        )

        headers = {}
        body = None

        if payload is not None:
            body = json.dumps(payload)
            headers["Content-Type"] = "application/json"

        try:
            connection.request(
                method,
                path,
                body=body,
                headers=headers,
            )
            response = connection.getresponse()
            raw = response.read()
            data = json.loads(raw) if raw else None
            return response.status, data
        finally:
            connection.close()

    def test_assign_success(self):
        self.api.assign.return_value = {
            "status": "assigned",
        }

        status, data = self.request(
            "POST",
            staging.ASSIGNMENTS_PATH,
            {
                "user_id": 42,
                "project_id": "PRJ-001",
                "role": "viewer",
            },
        )

        self.assertEqual(status, 201)
        self.assertEqual(data["status"], "assigned")
        self.api.assign.assert_called_once_with(
            1,
            {
                "user_id": 42,
                "project_id": "PRJ-001",
                "role": "viewer",
            },
        )

    def test_list_success(self):
        self.api.list_assignments.return_value = {
            "status": "ok",
            "assignments": [],
            "count": 0,
        }

        path = (
            staging.ASSIGNMENTS_PATH
            + "?"
            + urlencode({"project_id": "PRJ-001"})
        )

        status, data = self.request("GET", path)

        self.assertEqual(status, 200)
        self.assertEqual(data["count"], 0)
        self.api.list_assignments.assert_called_once_with(
            1,
            "PRJ-001",
        )

    def test_revoke_success(self):
        self.api.revoke.return_value = {
            "status": "revoked",
        }

        payload = {
            "user_id": 42,
            "project_id": "PRJ-001",
        }

        status, data = self.request(
            "POST",
            staging.REVOKE_PATH,
            payload,
        )

        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "revoked")
        self.api.revoke.assert_called_once_with(
            1,
            payload,
        )

    def test_missing_project_id(self):
        status, data = self.request(
            "GET",
            staging.ASSIGNMENTS_PATH,
        )

        self.assertEqual(status, 400)
        self.assertEqual(data["status"], "error")
        self.api.list_assignments.assert_not_called()

    def test_duplicate_project_id(self):
        status, data = self.request(
            "GET",
            staging.ASSIGNMENTS_PATH
            + "?project_id=A&project_id=B",
        )

        self.assertEqual(status, 400)
        self.api.list_assignments.assert_not_called()

    def test_unknown_query_field(self):
        status, data = self.request(
            "GET",
            staging.ASSIGNMENTS_PATH
            + "?project_id=A&admin=true",
        )

        self.assertEqual(status, 400)
        self.api.list_assignments.assert_not_called()

    def test_assignment_validation_error(self):
        self.api.assign.side_effect = AssignmentError(
            "Invalid assignment"
        )

        status, data = self.request(
            "POST",
            staging.ASSIGNMENTS_PATH,
            {"user_id": 42},
        )

        self.assertEqual(status, 400)
        self.assertEqual(data["status"], "error")

    def test_assignment_permission_denied(self):
        self.api.assign.side_effect = PermissionError(
            "Denied"
        )

        status, data = self.request(
            "POST",
            staging.ASSIGNMENTS_PATH,
            {
                "user_id": 42,
                "project_id": "PRJ-001",
            },
        )

        self.assertEqual(status, 403)
        self.assertEqual(data["message"], "Forbidden")

    def test_list_permission_denied(self):
        self.api.list_assignments.side_effect = (
            PermissionError("Denied")
        )

        status, data = self.request(
            "GET",
            staging.ASSIGNMENTS_PATH
            + "?project_id=PRJ-001",
        )

        self.assertEqual(status, 403)
        self.assertEqual(data["message"], "Forbidden")

    def test_revoke_permission_denied(self):
        self.api.revoke.side_effect = PermissionError(
            "Denied"
        )

        status, data = self.request(
            "POST",
            staging.REVOKE_PATH,
            {
                "user_id": 42,
                "project_id": "PRJ-001",
            },
        )

        self.assertEqual(status, 403)
        self.assertEqual(data["message"], "Forbidden")

    def test_database_unavailable(self):
        self.api.list_assignments.side_effect = (
            RuntimeError("Database unavailable")
        )

        status, data = self.request(
            "GET",
            staging.ASSIGNMENTS_PATH
            + "?project_id=PRJ-001",
        )

        self.assertEqual(status, 503)
        self.assertEqual(
            data["message"],
            "Service unavailable",
        )

    def test_missing_session(self):
        self.auth_patch.stop()

        with patch.object(
            staging.Handler,
            "authorize_user",
            return_value=None,
        ):
            status, data = self.request(
                "GET",
                staging.ASSIGNMENTS_PATH
                + "?project_id=PRJ-001",
            )

        self.assertEqual(status, 200)
        self.assertIsNone(data)
        self.api.list_assignments.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
