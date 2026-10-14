
"""IFC Digital - database-backed authentication service.

Standalone foundation for development and automated testing.
Does not expose HTTP endpoints or create real user accounts.
"""

import os
import time

import psycopg

from auth import create_session, verify_password, verify_session


class AuthenticationError(Exception):
    """Raised when login credentials are invalid."""


class AuthenticationService:
    def __init__(self, database_url=None, session_secret=None):
        self.database_url = database_url or os.environ.get(
            "DATABASE_URL"
        )
        self.session_secret = session_secret

        if not self.database_url:
            raise ValueError("DATABASE_URL is required")

        if not isinstance(self.session_secret, bytes):
            raise ValueError("Session secret must be bytes")

        if len(self.session_secret) < 32:
            raise ValueError("Session secret is too short")

    def connect(self):
        return psycopg.connect(
            self.database_url,
            connect_timeout=10
        )

    def find_user(self, email):
        """Find a user by normalized email address."""
        if not isinstance(email, str):
            return None

        email = email.strip().lower()

        if not email or len(email) > 254:
            return None

        with self.connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT
                        id,
                        email,
                        display_name,
                        password_hash,
                        active,
                        account_type,
                        subcontractor_id
                    FROM ifc_users
                    WHERE lower(email) = %s
                    """,
                    (email,)
                )

                row = cursor.fetchone()

        if row is None:
            return None

        return {
            "id": row[0],
            "email": row[1],
            "display_name": row[2],
            "password_hash": row[3],
            "active": row[4],
            "account_type": row[5],
            "subcontractor_id": row[6]
        }

    def login(self, email, password):
        """Verify credentials and issue a signed session."""
        if not isinstance(password, str):
            raise AuthenticationError("Invalid credentials")

        user = self.find_user(email)

        if user is None:
            raise AuthenticationError("Invalid credentials")

        if not user["active"]:
            raise AuthenticationError("Invalid credentials")

        stored_hash = user["password_hash"]

        if not stored_hash:
            raise AuthenticationError("Invalid credentials")

        if not verify_password(password, stored_hash):
            raise AuthenticationError("Invalid credentials")

        token = create_session(
            user["id"],
            self.session_secret,
            ttl_seconds=3600
        )

        return {
            "token": token,
            "expires_in": 3600,
            "user": {
                "id": user["id"],
                "email": user["email"],
                "display_name": user["display_name"]
            }
        }

    def authenticate(self, token):
        """Validate token and check current account status."""
        claims = verify_session(
            token,
            self.session_secret
        )

        if claims is None:
            return None

        with self.connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, email, display_name, active
                    FROM ifc_users
                    WHERE id = %s
                    """,
                    (claims["uid"],)
                )

                row = cursor.fetchone()

        if row is None or not row[3]:
            return None

        return {
            "id": row[0],
            "email": row[1],
            "display_name": row[2]
        }

    def get_roles(self, user_id):
        """Return currently active roles for a user."""
        with self.connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT r.code
                    FROM ifc_user_roles ur
                    JOIN ifc_roles r
                      ON r.id = ur.role_id
                    JOIN ifc_users u
                      ON u.id = ur.user_id
                    WHERE ur.user_id = %s
                      AND r.active = TRUE
                      AND u.active = TRUE
                    ORDER BY r.code
                    """,
                    (user_id,)
                )

                return [
                    row[0] for row in cursor.fetchall()
                ]

    def get_permissions(self, user_id):
        """Calculate role rights with individual overrides."""
        with self.connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT DISTINCT p.code
                    FROM ifc_user_roles ur
                    JOIN ifc_roles r
                      ON r.id = ur.role_id
                    JOIN ifc_role_permissions rp
                      ON rp.role_id = r.id
                    JOIN ifc_permissions p
                      ON p.id = rp.permission_id
                    JOIN ifc_users u
                      ON u.id = ur.user_id
                    WHERE ur.user_id = %s
                      AND r.active = TRUE
                      AND u.active = TRUE
                    """,
                    (user_id,)
                )

                permissions = {
                    row[0] for row in cursor.fetchall()
                }

                cursor.execute(
                    """
                    SELECT p.code, up.allowed
                    FROM ifc_user_permissions up
                    JOIN ifc_permissions p
                      ON p.id = up.permission_id
                    JOIN ifc_users u
                      ON u.id = up.user_id
                    WHERE up.user_id = %s
                      AND u.active = TRUE
                    """,
                    (user_id,)
                )

                for code, allowed in cursor.fetchall():
                    if allowed:
                        permissions.add(code)
                    else:
                        permissions.discard(code)

        return sorted(permissions)

    def has_permission(self, user_id, permission):
        """Check a specific permission."""
        return permission in self.get_permissions(user_id)

    def get_project_access(self, user_id, project_id):
        """Return a currently valid explicit project grant."""
        now = time.time()

        with self.connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    """
                    SELECT pa.access_role
                    FROM ifc_project_access pa
                    JOIN ifc_users u
                      ON u.id = pa.user_id
                    WHERE pa.user_id = %s
                      AND pa.project_id = %s
                      AND u.active = TRUE
                      AND pa.revoked_at IS NULL
                      AND (
                          pa.expires_at IS NULL
                          OR pa.expires_at > to_timestamp(%s)
                      )
                    """,
                    (user_id, project_id, now)
                )

                row = cursor.fetchone()

        return row[0] if row else None

    def can_access_project(
        self, user_id, project_id, permission
    ):
        """Require both a permission and project grant.

        This is a conservative foundation. Full authorization
        policy must be defined before production integration.
        """
        if not self.has_permission(user_id, permission):
            return False

        return self.get_project_access(
            user_id, project_id
        ) is not None
