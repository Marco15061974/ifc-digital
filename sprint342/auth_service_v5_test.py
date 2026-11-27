"""IFC Digital - Authentication Service V5 tests.

Sprint 342 - Staging V5.
Isolated authentication and revocation tests.
"""

import unittest
from unittest.mock import patch, Mock

import psycopg

from auth import create_session
from auth_service import AuthenticationService

from sprint342.auth_service_v5 import (
    AuthenticationServiceV5,
)


class AuthenticationServiceV5Tests(unittest.TestCase):

    def setUp(self):
        self.secret = b"x" * 32

        self.service = AuthenticationServiceV5(
            database_url="postgresql://test@localhost/test",
            session_secret=self.secret,
        )

        self.service.revocations = Mock()
        self.service.revocations.is_revoked.return_value = False
        self.service.revocations.revoke.return_value = True

        self.user = {
            "id": 1,
            "email": "admin@ifc-digital.test",
            "display_name": "IFC Test Admin",
        }

        self.token = create_session(
            1,
            self.secret,
            ttl_seconds=3600,
        )

        self.base_patch = patch.object(
            AuthenticationService,
            "authenticate",
            return_value=self.user,
        )

        self.base_auth = self.base_patch.start()
        self.addCleanup(self.base_patch.stop)

    def test_01_valid_session_accepted(self):
        result = self.service.authenticate(self.token)

        self.assertEqual(result, self.user)
        self.base_auth.assert_called_once_with(self.token)

    def test_02_invalid_token_rejected(self):
        result = self.service.authenticate("invalid")

        self.assertIsNone(result)
        self.base_auth.assert_not_called()
        self.service.revocations.is_revoked.assert_not_called()

    def test_03_missing_token_rejected(self):
        self.assertIsNone(
            self.service.authenticate(None)
        )

        self.base_auth.assert_not_called()

    def test_04_expired_token_rejected(self):
        token = create_session(
            1,
            self.secret,
            ttl_seconds=60,
            now=1000,
        )

        self.assertIsNone(
            self.service.authenticate(token)
        )

        self.base_auth.assert_not_called()

    def test_05_wrong_signature_rejected(self):
        token = create_session(
            1,
            b"y" * 32,
            ttl_seconds=3600,
        )

        self.assertIsNone(
            self.service.authenticate(token)
        )

        self.base_auth.assert_not_called()

    def test_06_revoked_session_rejected(self):
        self.service.revocations.is_revoked.return_value = True

        self.assertIsNone(
            self.service.authenticate(self.token)
        )

        self.base_auth.assert_not_called()

    def test_07_inactive_user_rejected(self):
        self.base_auth.return_value = None

        self.assertIsNone(
            self.service.authenticate(self.token)
        )

    def test_08_logout_revokes_session(self):
        self.assertTrue(
            self.service.logout(self.token)
        )

        self.service.revocations.revoke.assert_called_once()

        claims = (
            self.service.revocations.revoke.call_args.args[0]
        )

        self.assertEqual(claims["uid"], 1)
        self.assertEqual(len(claims["nonce"]), 32)

    def test_09_invalid_logout_rejected(self):
        self.assertFalse(
            self.service.logout("invalid")
        )

        self.service.revocations.revoke.assert_not_called()

    def test_10_inactive_user_logout_rejected(self):
        self.base_auth.return_value = None

        self.assertFalse(
            self.service.logout(self.token)
        )

        self.service.revocations.revoke.assert_not_called()

    def test_11_session_rejected_after_logout(self):
        revoked = set()

        def revoke(claims):
            revoked.add(claims["nonce"])
            return True

        self.service.revocations.revoke.side_effect = revoke

        self.service.revocations.is_revoked.side_effect = (
            lambda nonce: nonce in revoked
        )

        self.assertEqual(
            self.service.authenticate(self.token),
            self.user,
        )

        self.assertTrue(
            self.service.logout(self.token)
        )

        self.assertIsNone(
            self.service.authenticate(self.token)
        )

        other_token = create_session(
            1,
            self.secret,
            ttl_seconds=3600,
        )

        self.assertEqual(
            self.service.authenticate(other_token),
            self.user,
        )

    def test_12_database_failure_not_ignored(self):
        self.service.revocations.is_revoked.side_effect = (
            psycopg.OperationalError("Test database failure")
        )

        with self.assertRaises(psycopg.OperationalError):
            self.service.authenticate(self.token)

        self.base_auth.assert_not_called()

    def test_13_logout_database_failure_not_ignored(self):
        self.service.revocations.revoke.side_effect = (
            psycopg.OperationalError("Test database failure")
        )

        with self.assertRaises(psycopg.OperationalError):
            self.service.logout(self.token)

    def test_14_cleanup_delegated(self):
        self.service.revocations.purge_expired.return_value = 3

        self.assertEqual(
            self.service.purge_expired_revocations(),
            3,
        )

        self.service.revocations.purge_expired.assert_called_once_with()


if __name__ == "__main__":
    unittest.main(verbosity=2)
