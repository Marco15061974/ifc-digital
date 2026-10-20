
"""IFC Digital - Project Assignment Service.

Development module for assigning users to projects.
Uses the existing IFC authentication and permission
services. No HTTP endpoints are exposed here.
"""

from datetime import datetime, timezone

from project_permissions import (
    ProjectPermissionService,
    PROJECT_ROLE_PERMISSIONS,
)


class AssignmentError(Exception):
    """Raised for invalid assignment operations."""


class ProjectAssignmentService:
    """Manage explicit user access to IFC projects."""

    def __init__(self, auth_service):
        self.auth = auth_service
        self.permissions = ProjectPermissionService(
            auth_service
        )

    @staticmethod
    def validate_user_id(user_id):
        if (
            isinstance(user_id, bool)
            or not isinstance(user_id, int)
            or user_id <= 0
        ):
            raise AssignmentError("Invalid user ID")
        return user_id

    @staticmethod
    def validate_project_id(project_id):
        if not isinstance(project_id, str):
            raise AssignmentError("Invalid project ID")

        project_id = project_id.strip()

        if not project_id or len(project_id) > 128:
            raise AssignmentError("Invalid project ID")

        return project_id

    def require_manager(self, actor_id, project_id):
        """Only authorized project managers may assign."""

        self.validate_user_id(actor_id)
        project_id = self.validate_project_id(
            project_id
        )

        if not self.permissions.can_access(
            actor_id,
            project_id,
            "assignments.manage"
        ):
            raise PermissionError(
                "Project assignment management denied"
            )

    def assign(
        self,
        actor_id,
        user_id,
        project_id,
        role="viewer",
        expires_at=None,
    ):
        """Create a project assignment."""

        user_id = self.validate_user_id(user_id)
        project_id = self.validate_project_id(
            project_id
        )

        self.require_manager(actor_id, project_id)

        if role not in PROJECT_ROLE_PERMISSIONS:
            raise AssignmentError(
                "Unknown project role"
            )

        if expires_at is not None:
            if (
                not isinstance(expires_at, datetime)
                or expires_at.tzinfo is None
                or expires_at.utcoffset() is None
                or expires_at <= datetime.now(timezone.utc)
            ):
                raise AssignmentError(
                    "Invalid expiration date"
                )

        with self.auth.connect() as connection:
            with connection.cursor() as cursor:

                cursor.execute(
                    """
                    SELECT account_type
                    FROM ifc_users
                    WHERE id = %s AND active = TRUE
                    """,
                    (user_id,)
                )

                target = cursor.fetchone()

                if target is None:
                    raise AssignmentError(
                        "Target user is not active"
                    )

                if target[0] not in (
                    "internal", "external"
                ):
                    raise AssignmentError(
                        "Invalid account type"
                    )

                if (
                    target[0] == "external"
                    and role == "manager"
                ):
                    raise AssignmentError(
                        "External manager role denied"
                    )

                cursor.execute(
                    """
                    SELECT 1
                    FROM ifc_project_access
                    WHERE user_id = %s
                      AND project_id = %s
                      AND revoked_at IS NULL
                      AND (
                          expires_at IS NULL
                          OR expires_at > NOW()
                      )
                    LIMIT 1
                    """,
                    (user_id, project_id)
                )

                if cursor.fetchone() is not None:
                    raise AssignmentError(
                        "Active assignment already exists"
                    )

                cursor.execute(
                    """
                    INSERT INTO ifc_project_access
                        (
                            user_id,
                            project_id,
                            access_role,
                            expires_at
                        )
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        user_id,
                        project_id,
                        role,
                        expires_at
                    )
                )

        return {
            "status": "assigned",
            "user_id": user_id,
            "project_id": project_id,
            "role": role
        }

    def list_assignments(self, actor_id, project_id):
        """List active assignments for a project."""

        project_id = self.validate_project_id(
            project_id
        )

        self.require_manager(actor_id, project_id)

        with self.auth.connect() as connection:
            with connection.cursor() as cursor:

                cursor.execute(
                    """
                    SELECT
                        pa.user_id,
                        u.display_name,
                        pa.access_role,
                        pa.expires_at
                    FROM ifc_project_access pa
                    JOIN ifc_users u
                      ON u.id = pa.user_id
                    WHERE pa.project_id = %s
                      AND u.active = TRUE
                      AND pa.revoked_at IS NULL
                      AND (
                          pa.expires_at IS NULL
                          OR pa.expires_at > NOW()
                      )
                    ORDER BY u.display_name, pa.user_id
                    """,
                    (project_id,)
                )

                rows = cursor.fetchall()

        return [
            {
                "user_id": row[0],
                "display_name": row[1],
                "role": row[2],
                "expires_at": (
                    row[3].isoformat()
                    if row[3] is not None
                    else None
                )
            }
            for row in rows
        ]

    def revoke(self, actor_id, user_id, project_id):
        """Revoke all active grants for a user/project."""

        user_id = self.validate_user_id(user_id)
        project_id = self.validate_project_id(
            project_id
        )

        self.require_manager(actor_id, project_id)

        if actor_id == user_id:
            raise AssignmentError(
                "Self-revocation is not supported"
            )

        with self.auth.connect() as connection:
            with connection.cursor() as cursor:

                cursor.execute(
                    """
                    UPDATE ifc_project_access
                    SET revoked_at = NOW()
                    WHERE user_id = %s
                      AND project_id = %s
                      AND revoked_at IS NULL
                    """,
                    (user_id, project_id)
                )

                changed = cursor.rowcount

        return {
            "status": (
                "revoked" if changed else "not_found"
            ),
            "user_id": user_id,
            "project_id": project_id,
            "revoked_count": changed
        }
