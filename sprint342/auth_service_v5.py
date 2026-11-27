"""IFC Digital - Authentication Service V5.

Sprint 342 - Staging V5.
Persistent server-side session revocation.
"""

from auth import verify_session
from auth_service import AuthenticationService

from sprint342.session_revocations import (
    SessionRevocationStore,
)


class AuthenticationServiceV5(AuthenticationService):
    """Extend authentication with session revocation."""

    def __init__(
        self,
        database_url=None,
        session_secret=None,
    ):
        super().__init__(
            database_url=database_url,
            session_secret=session_secret,
        )

        self.revocations = SessionRevocationStore(
            self.database_url
        )

    def authenticate(self, token):
        """Reject invalid, expired or revoked sessions."""

        claims = verify_session(
            token,
            self.session_secret,
        )

        if claims is None:
            return None

        if self.revocations.is_revoked(
            claims["nonce"]
        ):
            return None

        return super().authenticate(token)

    def logout(self, token):
        """Persistently revoke a verified session."""

        claims = verify_session(
            token,
            self.session_secret,
        )

        if claims is None:
            return False

        user = super().authenticate(token)

        if user is None:
            return False

        return self.revocations.revoke(claims)

    def purge_expired_revocations(self):
        """Remove expired session revocation records."""

        return self.revocations.purge_expired()
