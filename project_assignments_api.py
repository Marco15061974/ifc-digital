
"""IFC Digital - Project Assignment API.

Staging-only request handler for project assignments.

Authentication is performed by the HTTP server.
Authorization is enforced by ProjectAssignmentService.
No production deployment without integration tests.
"""

from datetime import datetime
from project_assignments import (
    AssignmentError,
    ProjectAssignmentService,
)


class ProjectAssignmentAPI:
    """Handle validated project assignment requests."""

    def __init__(self, auth_service):
        self.service = ProjectAssignmentService(
            auth_service
        )

    @staticmethod
    def validate_payload(data, required, optional=()):
        if not isinstance(data, dict):
            raise AssignmentError("Invalid JSON payload")

        keys = set(data)
        required = set(required)
        allowed = required | set(optional)

        if not required.issubset(keys):
            raise AssignmentError("Missing required fields")

        if not keys.issubset(allowed):
            raise AssignmentError("Unknown fields")

        return data

    @staticmethod
    def parse_expiration(value):
        if value is None:
            return None

        if not isinstance(value, str):
            raise AssignmentError(
                "Invalid expiration date"
            )

        try:
            return datetime.fromisoformat(
                value.replace("Z", "+00:00")
            )
        except ValueError as exc:
            raise AssignmentError(
                "Invalid expiration date"
            ) from exc

    def assign(self, actor_id, data):
        """Assign a user to a project."""

        data = self.validate_payload(
            data,
            required=("user_id", "project_id"),
            optional=("role", "expires_at"),
        )

        role = data.get("role", "viewer")

        if not isinstance(role, str):
            raise AssignmentError("Invalid role")

        expires_at = self.parse_expiration(
            data.get("expires_at")
        )

        return self.service.assign(
            actor_id=actor_id,
            user_id=data["user_id"],
            project_id=data["project_id"],
            role=role,
            expires_at=expires_at,
        )

    def list_assignments(self, actor_id, project_id):
        """Return authorized project assignments."""

        assignments = self.service.list_assignments(
            actor_id=actor_id,
            project_id=project_id,
        )

        return {
            "status": "ok",
            "project_id": project_id,
            "assignments": assignments,
            "count": len(assignments),
        }

    def revoke(self, actor_id, data):
        """Revoke a user's project assignment."""

        data = self.validate_payload(
            data,
            required=("user_id", "project_id"),
        )

        return self.service.revoke(
            actor_id=actor_id,
            user_id=data["user_id"],
            project_id=data["project_id"],
        )
