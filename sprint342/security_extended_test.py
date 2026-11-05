"""IFC Digital - Sprint 342: Extended security tests.

Only mocked users and database connections.
No production services or customer records are accessed.
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from project_permissions import ProjectPermissionService
from project_assignments import ProjectAssignmentService


class ExtendedSecurityTests(unittest.TestCase):

    def setUp(self):
        self.auth = MagicMock()
        self.permissions = ProjectPermissionService(self.auth)
        self.assignments = ProjectAssignmentService(self.auth)

        self.user_id = 42
        self.stuttgart = "PRJ-STUTTGART"
        self.muenchen = "PRJ-MUENCHEN"

        connection = MagicMock()
        cursor = MagicMock()

        self.auth.connect.return_value.__enter__.return_value = connection
        connection.cursor.return_value.__enter__.return_value = cursor
        cursor.fetchone.return_value = ("internal", True)

        self.auth.has_permission.return_value = True

        def project_access(user_id, project_id):
            if user_id == self.user_id and project_id == self.stuttgart:
                return "editor"
            return None

        self.auth.get_project_access.side_effect = project_access

    def test_stuttgart_access_allowed(self):
        result = self.permissions.check(
            self.user_id, self.stuttgart, "projects.read"
        )
        self.assertTrue(result.allowed)

    def test_other_project_access_denied(self):
        result = self.permissions.check(
            self.user_id, self.muenchen, "projects.read"
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "no_valid_project_assignment")

    def test_revoked_access_denied_on_next_check(self):
        self.auth.get_project_access.return_value = None
        self.auth.get_project_access.side_effect = None

        result = self.permissions.check(
            self.user_id, self.stuttgart, "projects.read"
        )
        self.assertFalse(result.allowed)

    def test_editor_cannot_manage_assignments(self):
        result = self.permissions.check(
            self.user_id, self.stuttgart, "assignments.manage"
        )
        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, "project_role_restricted")

    def test_user_cannot_promote_self(self):
        self.assignments.permissions.can_access = MagicMock(
            return_value=False
        )

        with self.assertRaises(PermissionError):
            self.assignments.assign(
                self.user_id,
                self.user_id,
                self.stuttgart,
                role="manager",
            )

        self.auth.connect.assert_not_called()

    def test_user_cannot_revoke_other_access(self):
        self.assignments.permissions.can_access = MagicMock(
            return_value=False
        )

        with self.assertRaises(PermissionError):
            self.assignments.revoke(
                self.user_id,
                43,
                self.stuttgart,
            )

        self.auth.connect.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
