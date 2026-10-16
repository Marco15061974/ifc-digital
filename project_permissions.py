
"""IFC Digital - Project Permission Service.

Development module for project-specific authorization.
Default policy: deny unless explicitly permitted.
"""

from dataclasses import dataclass
from typing import Optional

from auth_service import AuthenticationService


PROJECT_PERMISSIONS = frozenset({
    "projects.read",
    "projects.manage",
    "measurements.read",
    "measurements.write",
    "reports.read",
    "reports.write",
    "reports.approve",
    "photos.read",
    "documents.read",
    "documents.upload",
    "documents.review",
    "subcontractors.manage",
    "assignments.manage",
    "finance.read",
})

VIEWER_PERMISSIONS = frozenset({
    "projects.read",
    "measurements.read",
    "reports.read",
    "photos.read",
    "documents.read",
})

EDITOR_PERMISSIONS = VIEWER_PERMISSIONS | frozenset({
    "measurements.write",
    "reports.write",
    "documents.upload",
})

APPROVER_PERMISSIONS = VIEWER_PERMISSIONS | frozenset({
    "reports.approve",
    "documents.review",
})

MANAGER_PERMISSIONS = PROJECT_PERMISSIONS

PROJECT_ROLE_PERMISSIONS = {
    "viewer": VIEWER_PERMISSIONS,
    "editor": EDITOR_PERMISSIONS,
    "approver": APPROVER_PERMISSIONS,
    "manager": MANAGER_PERMISSIONS,
}

EXTERNAL_RESTRICTED = frozenset({
    "finance.read",
    "projects.manage",
    "subcontractors.manage",
    "assignments.manage",
})


@dataclass(frozen=True)
class PermissionResult:
    allowed: bool
    reason: str
    project_id: Optional[str] = None
    permission: Optional[str] = None


class ProjectPermissionService:
    """Central authorization for project-related operations."""

    def __init__(self, auth_service: AuthenticationService):
        self.auth = auth_service

    def check(self, user_id, project_id, permission):
        """Evaluate permission and explicit project assignment."""

        if (
            isinstance(user_id, bool)
            or not isinstance(user_id, int)
            or user_id <= 0
        ):
            return PermissionResult(False, "invalid_user")

        if not isinstance(project_id, str):
            return PermissionResult(False, "invalid_project")

        project_id = project_id.strip()

        if not project_id or len(project_id) > 128:
            return PermissionResult(False, "invalid_project")

        if (
            not isinstance(permission, str)
            or permission not in PROJECT_PERMISSIONS
        ):
            return PermissionResult(
                False,
                "unknown_permission",
                project_id,
            )

        def deny(reason):
            return PermissionResult(
                False, reason, project_id, permission
            )

        # Confirm that the user is active.
        # Also identify external accounts.
        with self.auth.connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT account_type, active
                    FROM ifc_users
                    WHERE id = %s
                    """,
                    (user_id,),
                )
                user = cursor.fetchone()

        if user is None or not user[1]:
            return deny("inactive_or_missing_user")

        account_type = user[0]

        if account_type not in ("internal", "external"):
            return deny("invalid_account_type")

        # External users never receive financial
        # or administrative project permissions.
        if (
            account_type == "external"
            and permission in EXTERNAL_RESTRICTED
        ):
            return deny("external_account_restricted")

        # Global functional permission:
        # active roles and individual overrides.
        if not self.auth.has_permission(
            user_id, permission
        ):
            return deny("missing_permission")

        # Explicit project grant:
        # must not be revoked or expired.
        project_role = self.auth.get_project_access(
            user_id, project_id
        )

        if project_role not in PROJECT_ROLE_PERMISSIONS:
            return deny("no_valid_project_assignment")

        # Project role further restricts access.
        allowed_for_role = PROJECT_ROLE_PERMISSIONS[
            project_role
        ]

        if permission not in allowed_for_role:
            return deny("project_role_restricted")

        return PermissionResult(
            True,
            "access_granted",
            project_id,
            permission,
        )

    def can_access(self, user_id, project_id, permission):
        """Return True only when access is permitted."""
        return self.check(
            user_id, project_id, permission
        ).allowed

    def require_access(self, user_id, project_id, permission):
        """Raise PermissionError when access is denied."""
        result = self.check(
            user_id, project_id, permission
        )

        if not result.allowed:
            raise PermissionError(
                "Project access denied"
            )

        return result
