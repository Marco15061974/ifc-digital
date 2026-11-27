"""IFC Digital - Persistent session revocations.

Sprint 342 - Staging V5.
"""

import re
from collections.abc import Mapping

import psycopg


class SessionRevocationStore:
    """Store revoked sessions in PostgreSQL."""

    def __init__(self, database_url):
        if not database_url:
            raise ValueError("Database URL required")

        self.database_url = database_url

    def connect(self):
        return psycopg.connect(
            self.database_url,
            connect_timeout=10,
        )

    @staticmethod
    def validate_nonce(nonce):
        if not isinstance(nonce, str):
            raise ValueError("Invalid session nonce")

        if re.fullmatch(r"[0-9a-f]{32}", nonce) is None:
            raise ValueError("Invalid session nonce")

        return nonce

    @classmethod
    def validate_claims(cls, claims):
        if not isinstance(claims, Mapping):
            raise ValueError("Invalid session claims")

        nonce = cls.validate_nonce(
            claims.get("nonce")
        )

        user_id = claims.get("uid")
        expires_at = claims.get("exp")

        if type(user_id) is not int or user_id <= 0:
            raise ValueError("Invalid user ID")

        if type(expires_at) is not int or expires_at <= 0:
            raise ValueError("Invalid session expiry")

        return nonce, user_id, expires_at

    def is_revoked(self, nonce):
        """Check whether a session has been revoked."""

        nonce = self.validate_nonce(nonce)

        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM public.ifc_session_revocations
                    WHERE nonce = %s
                )
                """,
                (nonce,),
            ).fetchone()

            return bool(row[0])

    def revoke(self, verified_claims):
        """Revoke a previously verified session.

        Claims must originate from successful
        cryptographic token verification.
        """

        nonce, user_id, expires_at = (
            self.validate_claims(verified_claims)
        )

        with self.connect() as connection:
            row = connection.execute(
                """
                INSERT INTO public.ifc_session_revocations
                    (nonce, user_id, expires_at)
                SELECT
                    %s, %s, to_timestamp(%s)
                WHERE to_timestamp(%s) > NOW()
                ON CONFLICT (nonce) DO NOTHING
                RETURNING nonce
                """,
                (
                    nonce,
                    user_id,
                    expires_at,
                    expires_at,
                ),
            ).fetchone()

            if row is not None:
                return True

            existing = connection.execute(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM public.ifc_session_revocations
                    WHERE nonce = %s
                      AND user_id = %s
                )
                """,
                (nonce, user_id),
            ).fetchone()

            return bool(existing[0])

    def purge_expired(self):
        """Remove expired revocation records."""

        with self.connect() as connection:
            cursor = connection.execute(
                """
                DELETE FROM public.ifc_session_revocations
                WHERE expires_at <=
                    NOW() - INTERVAL '5 minutes'
                """
            )

            return cursor.rowcount
