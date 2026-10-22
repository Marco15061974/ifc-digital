
"""IFC Digital - Project Assignment API Tests.

Unit tests for project assignment request validation
and delegation to the existing assignment service.

No real database, users or projects are modified.
"""

import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from project_assignments import AssignmentError
from project_assignments_api import ProjectAssignmentAPI


class ProjectAssignmentAPITests(unittest.TestCase):

    def setUp(self):
        self.auth = MagicMock()

        with patch(
            "project_assignments_api.ProjectAssignmentService"
        ) as service_class:
            self.api = ProjectAssignmentAPI(self.auth)
            self.service = service_class.return_value

        self.actor_id = 1
        self.user_id = 42
        self.project_id = "PRJ-TEST-001"

    def valid_assignment(self):
        return {
            "user_id": self.user_id,
            "project_id": self.project_id,
            "role": "viewer",
        }

    def test_service_is_initialized(self):
        self.assertIsNotNone(self.api.service)

    def test_valid_assignment(self):
        self.service.assign.return_value = {
            "status": "assigned",
            "user_id": self.user_id,
        }

        result = self.api.assign(
            self.actor_id,
            self.valid_assignment(),
        )

        self.assertEqual(
            result["status"],
            "assigned",
        )

        self.service.assign.assert_called_once_with(
            actor_id=self.actor_id,
            user_id=self.user_id,
            project_id=self.project_id,
            role="viewer",
            expires_at=None,
        )

    def test_default_role_is_viewer(self):
        data = {
            "user_id": self.user_id,
            "project_id": self.project_id,
        }

        self.api.assign(self.actor_id, data)

        self.assertEqual(
            self.service.assign.call_args.kwargs["role"],
            "viewer",
        )

    def test_missing_user_is_rejected(self):
        data = {
            "project_id": self.project_id,
        }

        with self.assertRaises(AssignmentError):
            self.api.assign(self.actor_id, data)

        self.service.assign.assert_not_called()

    def test_missing_project_is_rejected(self):
        data = {
            "user_id": self.user_id,
        }

        with self.assertRaises(AssignmentError):
            self.api.assign(self.actor_id, data)

        self.service.assign.assert_not_called()

    def test_unknown_field_is_rejected(self):
        data = self.valid_assignment()
        data["admin_override"] = True

        with self.assertRaises(AssignmentError):
            self.api.assign(self.actor_id, data)

        self.service.assign.assert_not_called()

    def test_invalid_payload_is_rejected(self):
        for payload in (
            None,
            [],
            "invalid",
            123,
        ):
            with self.subTest(payload=payload):
                with self.assertRaises(AssignmentError):
                    self.api.assign(
                        self.actor_id,
                        payload,
                    )

        self.service.assign.assert_not_called()

    def test_non_string_role_is_rejected(self):
        data = self.valid_assignment()
        data["role"] = 123

        with self.assertRaises(AssignmentError):
            self.api.assign(self.actor_id, data)

        self.service.assign.assert_not_called()

    def test_valid_expiration(self):
        data = self.valid_assignment()
        data["expires_at"] = "2030-12-31T23:59:00Z"

        self.api.assign(self.actor_id, data)

        expiration = (
            self.service.assign.call_args
            .kwargs["expires_at"]
        )

        self.assertEqual(
            expiration,
            datetime(
                2030, 12, 31, 23, 59,
                tzinfo=timezone.utc,
            ),
        )

    def test_invalid_expiration_is_rejected(self):
        data = self.valid_assignment()
        data["expires_at"] = "not-a-date"

        with self.assertRaises(AssignmentError):
            self.api.assign(self.actor_id, data)

        self.service.assign.assert_not_called()

    def test_non_string_expiration_is_rejected(self):
        data = self.valid_assignment()
        data["expires_at"] = 12345

        with self.assertRaises(AssignmentError):
            self.api.assign(self.actor_id, data)

        self.service.assign.assert_not_called()

    def test_list_assignments(self):
        self.service.list_assignments.return_value = [
            {
                "user_id": 42,
                "role": "viewer",
            },
            {
                "user_id": 43,
                "role": "editor",
            },
        ]

        result = self.api.list_assignments(
            self.actor_id,
            self.project_id,
        )

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["count"], 2)
        self.assertEqual(
            result["project_id"],
            self.project_id,
        )

        self.service.list_assignments.assert_called_once_with(
            actor_id=self.actor_id,
            project_id=self.project_id,
        )

    def test_empty_assignment_list(self):
        self.service.list_assignments.return_value = []

        result = self.api.list_assignments(
            self.actor_id,
            self.project_id,
        )

        self.assertEqual(result["count"], 0)
        self.assertEqual(result["assignments"], [])

    def test_revoke_assignment(self):
        self.service.revoke.return_value = {
            "status": "revoked",
        }

        data = {
            "user_id": self.user_id,
            "project_id": self.project_id,
        }

        result = self.api.revoke(
            self.actor_id,
            data,
        )

        self.assertEqual(
            result["status"],
            "revoked",
        )

        self.service.revoke.assert_called_once_with(
            actor_id=self.actor_id,
            user_id=self.user_id,
            project_id=self.project_id,
        )

    def test_revoke_missing_user_is_rejected(self):
        data = {
            "project_id": self.project_id,
        }

        with self.assertRaises(AssignmentError):
            self.api.revoke(self.actor_id, data)

        self.service.revoke.assert_not_called()

    def test_revoke_unknown_field_is_rejected(self):
        data = {
            "user_id": self.user_id,
            "project_id": self.project_id,
            "force": True,
        }

        with self.assertRaises(AssignmentError):
            self.api.revoke(self.actor_id, data)

        self.service.revoke.assert_not_called()

    def test_assignment_permission_denied(self):
        self.service.assign.side_effect = PermissionError(
            "Access denied"
        )

        with self.assertRaises(PermissionError):
            self.api.assign(
                self.actor_id,
                self.valid_assignment(),
            )

    def test_list_permission_denied(self):
        self.service.list_assignments.side_effect = (
            PermissionError("Access denied")
        )

        with self.assertRaises(PermissionError):
            self.api.list_assignments(
                self.actor_id,
                self.project_id,
            )

    def test_revoke_permission_denied(self):
        self.service.revoke.side_effect = PermissionError(
            "Access denied"
        )

        data = {
            "user_id": self.user_id,
            "project_id": self.project_id,
        }

        with self.assertRaises(PermissionError):
            self.api.revoke(
                self.actor_id,
                data,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
