
"""IFC Digital - Project Assignment Tests.

Unit tests with simulated users and database.
No real employee or project records are changed.
"""

import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from project_assignments import (
    AssignmentError,
    ProjectAssignmentService,
)


class ProjectAssignmentTests(unittest.TestCase):

    def setUp(self):
        self.auth = MagicMock()
        self.service = ProjectAssignmentService(
            self.auth
        )

        self.actor_id = 1
        self.user_id = 42
        self.project_id = "PRJ-TEST-001"

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

    def test_valid_user_id(self):
        self.assertEqual(
            self.service.validate_user_id(42),
            42
        )

    def test_invalid_user_ids(self):
        for value in (None, True, 0, -1, "42"):
            with self.subTest(value=value):
                with self.assertRaises(AssignmentError):
                    self.service.validate_user_id(value)

    def test_valid_project_id(self):
        self.assertEqual(
            self.service.validate_project_id(
                " PRJ-TEST-001 "
            ),
            "PRJ-TEST-001"
        )

    def test_invalid_project_ids(self):
        for value in (None, "", " ", 123, "x" * 129):
            with self.subTest(value=value):
                with self.assertRaises(AssignmentError):
                    self.service.validate_project_id(value)

    def test_manager_permission_required(self):
        self.service.permissions.can_access.return_value = False

        with self.assertRaises(PermissionError):
            self.service.assign(
                self.actor_id,
                self.user_id,
                self.project_id
            )

        self.auth.connect.assert_not_called()

    def test_manager_can_assign_user(self):
        result = self.service.assign(
            self.actor_id,
            self.user_id,
            self.project_id,
            role="viewer"
        )

        self.assertEqual(
            result["status"],
            "assigned"
        )
        self.assertEqual(result["user_id"], 42)
        self.assertEqual(result["role"], "viewer")

        self.service.permissions.can_access.assert_called_with(
            self.actor_id,
            self.project_id,
            "assignments.manage"
        )

        self.assertEqual(
            self.cursor.execute.call_count,
            3
        )

    def test_invalid_role_is_rejected(self):
        with self.assertRaises(AssignmentError):
            self.service.assign(
                self.actor_id,
                self.user_id,
                self.project_id,
                role="superadmin"
            )

        self.auth.connect.assert_not_called()

    def test_inactive_user_is_rejected(self):
        self.cursor.fetchone.side_effect = [
            None
        ]

        with self.assertRaises(AssignmentError):
            self.service.assign(
                self.actor_id,
                self.user_id,
                self.project_id
            )

    def test_external_manager_is_rejected(self):
        self.cursor.fetchone.side_effect = [
            ("external",)
        ]

        with self.assertRaises(AssignmentError):
            self.service.assign(
                self.actor_id,
                self.user_id,
                self.project_id,
                role="manager"
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
                self.project_id
            )

    def test_expired_assignment_is_rejected(self):
        expired = (
            datetime.now(timezone.utc)
            - timedelta(days=1)
        )

        with self.assertRaises(AssignmentError):
            self.service.assign(
                self.actor_id,
                self.user_id,
                self.project_id,
                expires_at=expired
            )

    def test_future_expiration_is_accepted(self):
        future = (
            datetime.now(timezone.utc)
            + timedelta(days=30)
        )

        result = self.service.assign(
            self.actor_id,
            self.user_id,
            self.project_id,
            expires_at=future
        )

        self.assertEqual(
            result["status"],
            "assigned"
        )

    def test_list_assignments(self):
        future = (
            datetime.now(timezone.utc)
            + timedelta(days=30)
        )

        self.cursor.fetchall.return_value = [
            (42, "Test Monteur", "viewer", future),
            (43, "Test Büro", "editor", None),
        ]

        result = self.service.list_assignments(
            self.actor_id,
            self.project_id
        )

        self.assertEqual(len(result), 2)
        self.assertEqual(
            result[0]["display_name"],
            "Test Monteur"
        )
        self.assertEqual(
            result[1]["role"],
            "editor"
        )
        self.assertIsNone(
            result[1]["expires_at"]
        )

    def test_list_requires_manager(self):
        self.service.permissions.can_access.return_value = False

        with self.assertRaises(PermissionError):
            self.service.list_assignments(
                self.actor_id,
                self.project_id
            )

        self.auth.connect.assert_not_called()

    def test_revoke_assignment(self):
        self.cursor.rowcount = 1

        result = self.service.revoke(
            self.actor_id,
            self.user_id,
            self.project_id
        )

        self.assertEqual(
            result["status"],
            "revoked"
        )
        self.assertEqual(
            result["revoked_count"],
            1
        )

    def test_revoke_missing_assignment(self):
        self.cursor.rowcount = 0

        result = self.service.revoke(
            self.actor_id,
            self.user_id,
            self.project_id
        )

        self.assertEqual(
            result["status"],
            "not_found"
        )

    def test_self_revocation_is_rejected(self):
        with self.assertRaises(AssignmentError):
            self.service.revoke(
                self.actor_id,
                self.actor_id,
                self.project_id
            )

        self.auth.connect.assert_not_called()

    def test_revoke_requires_manager(self):
        self.service.permissions.can_access.return_value = False

        with self.assertRaises(PermissionError):
            self.service.revoke(
                self.actor_id,
                self.user_id,
                self.project_id
            )

        self.auth.connect.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
