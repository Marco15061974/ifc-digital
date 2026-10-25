
"""IFC Digital - Project Management Backend Tests.

Tests assignment service and permission enforcement.
Uses simulated database connections only.
"""

import unittest
from unittest.mock import MagicMock

from project_assignments import (
    AssignmentError,
    ProjectAssignmentService,
)


class ProjectManagementBackendTests(unittest.TestCase):

    def setUp(self):
        self.auth = MagicMock()
        self.service = ProjectAssignmentService(
            self.auth
        )

        self.actor_id = 1
        self.user_id = 42
        self.project_id = "IFC-DEMO-001"

        self.service.permissions.can_access = (
            MagicMock(return_value=True)
        )

        self.connection = MagicMock()
        self.cursor = MagicMock()

        self.auth.connect.return_value.__enter__.return_value = (
            self.connection
        )

        self.connection.cursor.return_value.__enter__.return_value = (
            self.cursor
        )

        self.cursor.fetchone.side_effect = [
            ("internal",),
            None,
        ]

    def test_manager_can_assign_employee(self):
        result = self.service.assign(
            self.actor_id,
            self.user_id,
            self.project_id,
            role="editor",
        )

        self.assertEqual(
            result["status"],
            "assigned",
        )
        self.assertEqual(
            result["role"],
            "editor",
        )

        self.service.permissions.can_access.assert_called_with(
            self.actor_id,
            self.project_id,
            "assignments.manage",
        )

    def test_unauthorized_assignment_is_denied(self):
        self.service.permissions.can_access.return_value = False

        with self.assertRaises(PermissionError):
            self.service.assign(
                self.actor_id,
                self.user_id,
                self.project_id,
            )

        self.auth.connect.assert_not_called()

    def test_invalid_employee_is_rejected(self):
        with self.assertRaises(AssignmentError):
            self.service.assign(
                self.actor_id,
                0,
                self.project_id,
            )

        self.auth.connect.assert_not_called()

    def test_external_manager_is_rejected(self):
        self.cursor.fetchone.side_effect = [
            ("external",),
        ]

        with self.assertRaises(AssignmentError):
            self.service.assign(
                self.actor_id,
                self.user_id,
                self.project_id,
                role="manager",
            )

    def test_duplicate_assignment_is_rejected(self):
        self.cursor.fetchone.side_effect = [
            ("internal",),
            (1,),
        ]

        with self.assertRaises(AssignmentError):
            self.service.assign(
                self.actor_id,
                self.user_id,
                self.project_id,
            )

    def test_assignments_can_be_listed(self):
        self.cursor.fetchall.return_value = [
            (42, "Demo-Monteur", "editor", None),
        ]

        result = self.service.list_assignments(
            self.actor_id,
            self.project_id,
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["display_name"],
            "Demo-Monteur",
        )
        self.assertEqual(
            result[0]["role"],
            "editor",
        )

    def test_unauthorized_listing_is_denied(self):
        self.service.permissions.can_access.return_value = False

        with self.assertRaises(PermissionError):
            self.service.list_assignments(
                self.actor_id,
                self.project_id,
            )

        self.auth.connect.assert_not_called()

    def test_assignment_can_be_revoked(self):
        self.cursor.rowcount = 1

        result = self.service.revoke(
            self.actor_id,
            self.user_id,
            self.project_id,
        )

        self.assertEqual(
            result["status"],
            "revoked",
        )
        self.assertEqual(
            result["revoked_count"],
            1,
        )

    def test_unauthorized_revocation_is_denied(self):
        self.service.permissions.can_access.return_value = False

        with self.assertRaises(PermissionError):
            self.service.revoke(
                self.actor_id,
                self.user_id,
                self.project_id,
            )

        self.auth.connect.assert_not_called()

    def test_self_revocation_is_rejected(self):
        with self.assertRaises(AssignmentError):
            self.service.revoke(
                self.actor_id,
                self.actor_id,
                self.project_id,
            )

        self.auth.connect.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
