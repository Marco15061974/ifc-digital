
"""IFC Digital - Project Permission Tests.

Unit tests using simulated authentication and database data.
No real accounts or customer projects are used.
"""

import unittest
from unittest.mock import MagicMock

from project_permissions import (
    ProjectPermissionService,
    PROJECT_PERMISSIONS,
)


class ProjectPermissionTests(unittest.TestCase):

    def setUp(self):
        self.auth = MagicMock()
        self.service = ProjectPermissionService(self.auth)

        self.user_id = 42
        self.project_id = "PRJ-TEST-001"

        self.auth.has_permission.return_value = True
        self.auth.get_project_access.return_value = "editor"

        self.cursor = MagicMock()
        self.cursor.fetchone.return_value = ("internal", True)

        self.connection = MagicMock()
        self.connection.cursor.return_value.__enter__.return_value = (
            self.cursor
        )

        self.auth.connect.return_value.__enter__.return_value = (
            self.connection
        )

    def check(self, permission):
        return self.service.check(
            self.user_id,
            self.project_id,
            permission,
        )

    def test_editor_can_read_project(self):
        result = self.check("projects.read")
        self.assertTrue(result.allowed)
        self.assertEqual(result.reason, "access_granted")

    def test_editor_can_write_measurements(self):
        result = self.check("measurements.write")
        self.assertTrue(result.allowed)

    def test_editor_cannot_read_finances(self):
        result = self.check("finance.read")
        self.assertFalse(result.allowed)
        self.assertEqual(
            result.reason,
            "project_role_restricted",
        )

    def test_viewer_cannot_edit_measurements(self):
        self.auth.get_project_access.return_value = "viewer"

        result = self.check("measurements.write")

        self.assertFalse(result.allowed)
        self.assertEqual(
            result.reason,
            "project_role_restricted",
        )

    def test_viewer_can_read_reports(self):
        self.auth.get_project_access.return_value = "viewer"

        result = self.check("reports.read")

        self.assertTrue(result.allowed)

    def test_approver_can_approve_reports(self):
        self.auth.get_project_access.return_value = "approver"

        result = self.check("reports.approve")

        self.assertTrue(result.allowed)

    def test_approver_cannot_edit_measurements(self):
        self.auth.get_project_access.return_value = "approver"

        result = self.check("measurements.write")

        self.assertFalse(result.allowed)

    def test_manager_can_access_known_permissions(self):
        self.auth.get_project_access.return_value = "manager"

        for permission in PROJECT_PERMISSIONS:
            with self.subTest(permission=permission):
                self.assertTrue(self.check(permission).allowed)

    def test_missing_global_permission(self):
        self.auth.has_permission.return_value = False

        result = self.check("projects.read")

        self.assertFalse(result.allowed)
        self.assertEqual(
            result.reason,
            "missing_permission",
        )

    def test_missing_project_assignment(self):
        self.auth.get_project_access.return_value = None

        result = self.check("projects.read")

        self.assertFalse(result.allowed)
        self.assertEqual(
            result.reason,
            "no_valid_project_assignment",
        )

    def test_unknown_project_role(self):
        self.auth.get_project_access.return_value = "unknown"

        result = self.check("projects.read")

        self.assertFalse(result.allowed)

    def test_inactive_user(self):
        self.cursor.fetchone.return_value = ("internal", False)

        result = self.check("projects.read")

        self.assertFalse(result.allowed)
        self.assertEqual(
            result.reason,
            "inactive_or_missing_user",
        )

    def test_missing_user(self):
        self.cursor.fetchone.return_value = None

        result = self.check("projects.read")

        self.assertFalse(result.allowed)

    def test_external_cannot_read_finances(self):
        self.cursor.fetchone.return_value = ("external", True)
        self.auth.get_project_access.return_value = "manager"

        result = self.check("finance.read")

        self.assertFalse(result.allowed)
        self.assertEqual(
            result.reason,
            "external_account_restricted",
        )

    def test_external_cannot_manage_projects(self):
        self.cursor.fetchone.return_value = ("external", True)
        self.auth.get_project_access.return_value = "manager"

        result = self.check("projects.manage")

        self.assertFalse(result.allowed)

    def test_external_can_read_assigned_project(self):
        self.cursor.fetchone.return_value = ("external", True)

        result = self.check("projects.read")

        self.assertTrue(result.allowed)

    def test_unknown_permission_is_denied(self):
        result = self.check("admin.delete_everything")

        self.assertFalse(result.allowed)
        self.assertEqual(
            result.reason,
            "unknown_permission",
        )

    def test_invalid_user_is_denied(self):
        for user_id in (None, 0, -1, True, "42"):
            with self.subTest(user_id=user_id):
                result = self.service.check(
                    user_id,
                    self.project_id,
                    "projects.read",
                )
                self.assertFalse(result.allowed)

    def test_invalid_project_is_denied(self):
        for project_id in (None, "", " ", 123):
            with self.subTest(project_id=project_id):
                result = self.service.check(
                    self.user_id,
                    project_id,
                    "projects.read",
                )
                self.assertFalse(result.allowed)

    def test_can_access_returns_boolean(self):
        self.assertTrue(
            self.service.can_access(
                self.user_id,
                self.project_id,
                "projects.read",
            )
        )

        self.auth.has_permission.return_value = False

        self.assertFalse(
            self.service.can_access(
                self.user_id,
                self.project_id,
                "projects.read",
            )
        )

    def test_require_access_denies_without_permission(self):
        self.auth.has_permission.return_value = False

        with self.assertRaises(PermissionError):
            self.service.require_access(
                self.user_id,
                self.project_id,
                "projects.read",
            )

    def test_require_access_allows_valid_user(self):
        result = self.service.require_access(
            self.user_id,
            self.project_id,
            "projects.read",
        )

        self.assertTrue(result.allowed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
