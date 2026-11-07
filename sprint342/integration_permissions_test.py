
"""IFC Digital - Sprint 342 - Integration permissions test.

Isolated integration tests using the existing IFC services.
No real database, HTTP server or customer data is used.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from auth_service import AuthenticationService
from project_assignments import ProjectAssignmentService
from project_permissions import ProjectPermissionService


class FakeDatabase:
    """Shared simulated project and user records."""

    def __init__(self):
        self.users = {
            1: ("internal", True),
            42: ("internal", True),
            43: ("external", True),
        }
        self.grants = {
            (1, "PRJ-TEST-001"): "manager",
        }
        self.permissions = {
            1: {"assignments.manage"},
            42: {"projects.read", "reports.write"},
            43: {"projects.read", "finance.read"},
        }

    def connect(self):
        database = self
        connection = MagicMock()
        cursor = MagicMock()

        connection.__enter__.return_value = connection
        connection.cursor.return_value.__enter__.return_value = cursor

        def execute(sql, params):
            query = " ".join(sql.split()).upper()
            cursor.rowcount = 0

            if "SELECT ACCOUNT_TYPE, ACTIVE" in query:
                cursor.fetchone.return_value = database.users.get(
                    params[0]
                )
            elif "SELECT ACCOUNT_TYPE" in query:
                user = database.users.get(params[0])
                cursor.fetchone.return_value = (
                    (user[0],) if user and user[1] else None
                )
            elif "SELECT 1 FROM IFC_PROJECT_ACCESS" in query:
                key = (params[0], params[1])
                cursor.fetchone.return_value = (
                    (1,) if key in database.grants else None
                )
            elif "INSERT INTO IFC_PROJECT_ACCESS" in query:
                user_id, project_id, role, _ = params
                database.grants[(user_id, project_id)] = role
            elif "UPDATE IFC_PROJECT_ACCESS" in query:
                key = (params[0], params[1])
                if key in database.grants:
                    del database.grants[key]
                    cursor.rowcount = 1

        cursor.execute.side_effect = execute
        return connection


class IntegrationPermissionsTests(unittest.TestCase):

    def setUp(self):
        self.db = FakeDatabase()
        self.auth = AuthenticationService(
            database_url="mock://ifc-test",
            session_secret=b"ifc-test-secret-" * 3,
        )

        self.auth.connect = self.db.connect
        self.auth.has_permission = (
            lambda uid, permission:
            permission in self.db.permissions.get(uid, set())
        )
        self.auth.get_project_access = (
            lambda uid, project:
            self.db.grants.get((uid, project))
        )

        self.assignments = ProjectAssignmentService(self.auth)
        self.access = ProjectPermissionService(self.auth)
        self.project = "PRJ-TEST-001"

    def test_01_no_assignment_denies_access(self):
        result = self.access.check(
            42, self.project, "projects.read"
        )
        self.assertFalse(result.allowed)
        self.assertEqual(
            result.reason, "no_valid_project_assignment"
        )

    def test_02_manager_assigns_monteur(self):
        result = self.assignments.assign(
            1, 42, self.project, role="viewer"
        )
        self.assertEqual(result["status"], "assigned")
        self.assertTrue(
            self.access.can_access(
                42, self.project, "projects.read"
            )
        )

    def test_03_viewer_cannot_write_reports(self):
        self.assignments.assign(
            1, 42, self.project, role="viewer"
        )
        result = self.access.check(
            42, self.project, "reports.write"
        )
        self.assertFalse(result.allowed)
        self.assertEqual(
            result.reason, "project_role_restricted"
        )

    def test_04_other_project_is_denied(self):
        self.assignments.assign(
            1, 42, self.project, role="viewer"
        )
        self.assertFalse(
            self.access.can_access(
                42, "PRJ-OTHER", "projects.read"
            )
        )

    def test_05_revocation_removes_access(self):
        self.assignments.assign(
            1, 42, self.project, role="viewer"
        )
        result = self.assignments.revoke(
            1, 42, self.project
        )
        self.assertEqual(result["status"], "revoked")
        self.assertFalse(
            self.access.can_access(
                42, self.project, "projects.read"
            )
        )

    def test_06_external_finance_is_denied(self):
        self.db.grants[(43, self.project)] = "viewer"
        result = self.access.check(
            43, self.project, "finance.read"
        )
        self.assertFalse(result.allowed)
        self.assertEqual(
            result.reason, "external_account_restricted"
        )

    def test_07_missing_session_is_denied(self):
        with patch(
            "auth_service.verify_session",
            return_value=None,
        ):
            self.assertIsNone(
                self.auth.authenticate("invalid-token")
            )

    def test_08_unauthorized_user_cannot_assign(self):
        with self.assertRaises(PermissionError):
            self.assignments.assign(
                42, 43, self.project, role="viewer"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
