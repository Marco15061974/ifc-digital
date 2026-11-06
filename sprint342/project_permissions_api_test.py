
"""IFC Digital - Sprint 342
Tests for the project permission API adapter.

Only mock users and mock permission services.
No database or network connection.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from project_permissions import PermissionResult


def check_permission(session_user, payload, service):
    """Check access using the authenticated session identity."""

    if not isinstance(session_user, dict):
        return 401, {"status": "error", "message": "Unauthorized"}

    user_id = session_user.get("id")

    if type(user_id) is not int or user_id <= 0:
        return 401, {"status": "error", "message": "Unauthorized"}

    if not isinstance(payload, dict):
        return 400, {"status": "error", "message": "Invalid request"}

    if set(payload) != {"project_id", "permission"}:
        return 400, {"status": "error", "message": "Invalid request"}

    project_id = payload["project_id"]
    permission = payload["permission"]

    if (
        not isinstance(project_id, str)
        or not project_id.strip()
        or len(project_id) > 128
        or not isinstance(permission, str)
        or not permission.strip()
    ):
        return 400, {"status": "error", "message": "Invalid request"}

    result = service.check(user_id, project_id.strip(), permission)

    return 200, {
        "status": "ok",
        "allowed": result.allowed,
        "reason": result.reason,
    }


class ProjectPermissionAPITests(unittest.TestCase):

    def setUp(self):
        self.service = MagicMock()
        self.session = {"id": 42}
        self.payload = {
            "project_id": "PRJ-STUTTGART",
            "permission": "reports.approve",
        }

    def test_authorized_approval(self):
        self.service.check.return_value = PermissionResult(
            True, "access_granted"
        )

        status, response = check_permission(
            self.session, self.payload, self.service
        )

        self.assertEqual(status, 200)
        self.assertTrue(response["allowed"])

    def test_finance_access_denied(self):
        self.service.check.return_value = PermissionResult(
            False, "external_account_restricted"
        )

        payload = {
            "project_id": "PRJ-STUTTGART",
            "permission": "finance.read",
        }

        status, response = check_permission(
            self.session, payload, self.service
        )

        self.assertEqual(status, 200)
        self.assertFalse(response["allowed"])

    def test_missing_session_denied(self):
        status, response = check_permission(
            None, self.payload, self.service
        )

        self.assertEqual(status, 401)
        self.service.check.assert_not_called()

    def test_client_cannot_supply_user_id(self):
        payload = dict(self.payload)
        payload["user_id"] = 999

        status, response = check_permission(
            self.session, payload, self.service
        )

        self.assertEqual(status, 400)
        self.service.check.assert_not_called()

    def test_invalid_project_denied(self):
        payload = {
            "project_id": "",
            "permission": "reports.approve",
        }

        status, response = check_permission(
            self.session, payload, self.service
        )

        self.assertEqual(status, 400)
        self.service.check.assert_not_called()

    def test_session_identity_is_used(self):
        self.service.check.return_value = PermissionResult(
            True, "access_granted"
        )

        check_permission(self.session, self.payload, self.service)

        self.service.check.assert_called_once_with(
            42, "PRJ-STUTTGART", "reports.approve"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
