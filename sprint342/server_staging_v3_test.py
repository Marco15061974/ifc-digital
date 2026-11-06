
"""IFC Digital - Sprint 342 - Staging V3 tests.

Tests use mocks only. No real database, server,
customer data or network requests.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import server_staging_v3 as v3


class StagingV3Tests(unittest.TestCase):

    def setUp(self):
        self.handler = object.__new__(v3.Handler)
        self.handler.path = (
            "/api/v1/project-permissions/check"
            "?project_id=PRJ-TEST-001"
            "&permission=projects.read"
        )
        self.handler.send_json = MagicMock()
        self.handler.authorize_user = MagicMock(
            return_value={"id": 42}
        )

    def test_missing_session_is_denied(self):
        self.handler.authorize_user.return_value = None

        self.handler.do_GET()

        self.handler.authorize_user.assert_called_once()
        self.handler.send_json.assert_not_called()

    def test_invalid_permission_is_rejected(self):
        self.handler.path = (
            "/api/v1/project-permissions/check"
            "?project_id=PRJ-TEST-001"
            "&permission=unknown.permission"
        )

        self.handler.do_GET()

        self.handler.send_json.assert_called_once()
        self.assertEqual(
            self.handler.send_json.call_args.args[0],
            400,
        )

    def test_missing_project_is_rejected(self):
        self.handler.path = (
            "/api/v1/project-permissions/check"
            "?permission=projects.read"
        )

        self.handler.do_GET()

        self.assertEqual(
            self.handler.send_json.call_args.args[0],
            400,
        )

    @patch.object(v3, "ProjectPermissionService")
    @patch.object(
        v3.server_staging_v2.server,
        "authentication_service",
    )
    def test_allowed_project_access(
        self, mock_auth, mock_service
    ):
        mock_service.return_value.check.return_value = (
            MagicMock(allowed=True)
        )

        self.handler.do_GET()

        mock_service.return_value.check.assert_called_once_with(
            42, "PRJ-TEST-001", "projects.read"
        )

        self.assertEqual(
            self.handler.send_json.call_args.args[0],
            200,
        )

    @patch.object(v3, "ProjectPermissionService")
    @patch.object(
        v3.server_staging_v2.server,
        "authentication_service",
    )
    def test_denied_project_access(
        self, mock_auth, mock_service
    ):
        mock_service.return_value.check.return_value = (
            MagicMock(allowed=False)
        )

        self.handler.do_GET()

        self.assertEqual(
            self.handler.send_json.call_args.args[0],
            403,
        )

    @patch.object(v3, "ProjectPermissionService")
    @patch.object(
        v3.server_staging_v2.server,
        "authentication_service",
    )
    def test_database_error_returns_503(
        self, mock_auth, mock_service
    ):
        mock_service.return_value.check.side_effect = (
            RuntimeError("Simulated database error")
        )

        with patch.object(v3.logging, "exception"):
            self.handler.do_GET()

        self.assertEqual(
            self.handler.send_json.call_args.args[0],
            503,
        )

    def test_duplicate_parameters_rejected(self):
        self.handler.path = (
            "/api/v1/project-permissions/check"
            "?project_id=A&project_id=B"
            "&permission=projects.read"
        )

        self.handler.do_GET()

        self.assertEqual(
            self.handler.send_json.call_args.args[0],
            400,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
