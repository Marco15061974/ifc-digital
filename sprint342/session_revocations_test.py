"""IFC Digital - Session revocation integration tests.

Sprint 342 - Staging V5.
Run only against the isolated GitHub test database.
"""

import os
import time
import secrets
import unittest

import psycopg

from session_revocations import SessionRevocationStore


TEST_DATABASE_URL = (
    "postgresql://ifc_test:ifc_test_only"
    "@127.0.0.1:5432/ifc_session_test"
)


class SessionRevocationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        database_url = os.environ.get("DATABASE_URL")

        if database_url != TEST_DATABASE_URL:
            raise RuntimeError(
                "ABORT: Isolated test database required"
            )

        if os.environ.get("GITHUB_ACTIONS") != "true":
            raise RuntimeError(
                "ABORT: GitHub Actions required"
            )

        cls.store = SessionRevocationStore(database_url)

        with cls.store.connect() as conn:
            database = conn.execute(
                "SELECT current_database()"
            ).fetchone()[0]

            if database != "ifc_session_test":
                raise RuntimeError("Wrong database")

    def setUp(self):
        self.nonce = secrets.token_hex(16)

        with self.store.connect() as conn:
            self.user_id = conn.execute(
                """
                INSERT INTO public.ifc_users
                    (email, display_name)
                VALUES (%s, %s)
                RETURNING id
                """,
                (
                    f"{self.nonce}@ifc.test",
                    "Session Revocation Test",
                ),
            ).fetchone()[0]

        self.claims = {
            "nonce": self.nonce,
            "uid": self.user_id,
            "exp": int(time.time()) + 3600,
        }

    def tearDown(self):
        with self.store.connect() as conn:
            conn.execute(
                """
                DELETE FROM public.ifc_users
                WHERE id = %s
                """,
                (self.user_id,),
            )

    def test_01_new_session_not_revoked(self):
        self.assertFalse(
            self.store.is_revoked(self.nonce)
        )

    def test_02_revoke_session(self):
        self.assertTrue(
            self.store.revoke(self.claims)
        )

        self.assertTrue(
            self.store.is_revoked(self.nonce)
        )

    def test_03_repeated_revocation(self):
        self.assertTrue(
            self.store.revoke(self.claims)
        )

        self.assertTrue(
            self.store.revoke(self.claims)
        )

        with self.store.connect() as conn:
            count = conn.execute(
                """
                SELECT COUNT(*)
                FROM public.ifc_session_revocations
                WHERE nonce = %s
                """,
                (self.nonce,),
            ).fetchone()[0]

        self.assertEqual(count, 1)

    def test_04_persistent_revocation(self):
        self.store.revoke(self.claims)

        new_store = SessionRevocationStore(
            TEST_DATABASE_URL
        )

        self.assertTrue(
            new_store.is_revoked(self.nonce)
        )

    def test_05_other_session_unaffected(self):
        self.store.revoke(self.claims)

        other_nonce = secrets.token_hex(16)

        self.assertFalse(
            self.store.is_revoked(other_nonce)
        )

    def test_06_invalid_nonce_rejected(self):
        for nonce in (
            None,
            "",
            "invalid",
            "A" * 32,
            "a" * 31,
            "a" * 33,
        ):
            with self.subTest(nonce=nonce):
                with self.assertRaises(ValueError):
                    self.store.is_revoked(nonce)

    def test_07_invalid_user_rejected(self):
        for user_id in (None, 0, -1, True, "1"):
            with self.subTest(user_id=user_id):
                claims = dict(self.claims)
                claims["uid"] = user_id

                with self.assertRaises(ValueError):
                    self.store.revoke(claims)

    def test_08_invalid_expiry_rejected(self):
        for expiry in (None, 0, -1, True, "123"):
            with self.subTest(expiry=expiry):
                claims = dict(self.claims)
                claims["exp"] = expiry

                with self.assertRaises(ValueError):
                    self.store.revoke(claims)

    def test_09_expired_session_not_inserted(self):
        claims = dict(self.claims)
        claims["exp"] = int(time.time()) - 60

        self.assertFalse(
            self.store.revoke(claims)
        )

        self.assertFalse(
            self.store.is_revoked(self.nonce)
        )

    def test_10_unknown_user_rejected(self):
        claims = dict(self.claims)

        claims["uid"] = 9223372036854775807

        with self.assertRaises(
            psycopg.errors.ForeignKeyViolation
        ):
            self.store.revoke(claims)

    def test_11_purge_expired_records(self):
        with self.store.connect() as conn:
            conn.execute(
                """
                INSERT INTO public.ifc_session_revocations
                    (nonce, user_id, revoked_at, expires_at)
                VALUES (
                    %s,
                    %s,
                    NOW() - INTERVAL '2 hours',
                    NOW() - INTERVAL '1 hour'
                )
                """,
                (self.nonce, self.user_id),
            )

        self.assertTrue(
            self.store.is_revoked(self.nonce)
        )

        self.assertGreaterEqual(
            self.store.purge_expired(), 1
        )

        self.assertFalse(
            self.store.is_revoked(self.nonce)
        )

    def test_12_active_revocation_preserved(self):
        self.store.revoke(self.claims)
        self.store.purge_expired()

        self.assertTrue(
            self.store.is_revoked(self.nonce)
        )

    def test_13_cleanup_grace_period(self):
        with self.store.connect() as conn:
            conn.execute(
                """
                INSERT INTO public.ifc_session_revocations
                    (nonce, user_id, revoked_at, expires_at)
                VALUES (
                    %s,
                    %s,
                    NOW() - INTERVAL '1 hour',
                    NOW() - INTERVAL '1 minute'
                )
                """,
                (self.nonce, self.user_id),
            )

        self.store.purge_expired()

        self.assertTrue(
            self.store.is_revoked(self.nonce)
        )

    def test_14_database_failure_not_ignored(self):
        from unittest.mock import patch

        with patch.object(
            self.store,
            "connect",
            side_effect=psycopg.OperationalError(
                "Simulated database failure"
            ),
        ):
            with self.assertRaises(
                psycopg.OperationalError
            ):
                self.store.is_revoked(self.nonce)

            with self.assertRaises(
                psycopg.OperationalError
            ):
                self.store.revoke(self.claims)


if __name__ == "__main__":
    unittest.main(verbosity=2)
