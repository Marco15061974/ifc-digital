"""IFC Digital: password hashing and signed session tokens.

Foundation only. The application server must enforce authorization,
revocation, HTTPS, rate limiting and secure session transport.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time

_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SALT_BYTES = 16
_KEY_BYTES = 32
_MAX_SESSION_SECONDS = 8 * 60 * 60


def _encode(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode(value):
    if not isinstance(value, str):
        raise ValueError("Invalid encoding")
    return base64.b64decode(
        value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
    )


def hash_password(password):
    """Return a salted scrypt password verifier, never the password itself."""
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a nonempty string")
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_KEY_BYTES
    )
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${_encode(salt)}${_encode(digest)}"


def verify_password(password, stored_hash):
    """Verify a password without comparing secrets using ordinary equality."""
    if not isinstance(password, str) or not isinstance(stored_hash, str):
        return False
    try:
        algorithm, n, r, p, salt, expected = stored_hash.split("$")
        if (algorithm, int(n), int(r), int(p)) != (
            "scrypt", _SCRYPT_N, _SCRYPT_R, _SCRYPT_P
        ):
            return False
        salt_bytes = _decode(salt)
        expected_bytes = _decode(expected)
        if len(salt_bytes) != _SALT_BYTES or len(expected_bytes) != _KEY_BYTES:
            return False
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=salt_bytes,
            n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=_KEY_BYTES
        )
        return hmac.compare_digest(actual, expected_bytes)
    except (ValueError, TypeError, OverflowError):
        return False


def _sign(message, secret):
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError("Session secret must be at least 32 random bytes")
    return hmac.new(secret, message.encode("ascii"), hashlib.sha256).digest()


def create_session(user_id, secret, ttl_seconds=3600, now=None):
    """Create a signed session token for a database-backed user ID."""
    if isinstance(user_id, bool) or not isinstance(user_id, int) or user_id <= 0:
        raise ValueError("Invalid user ID")
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        raise ValueError("Invalid session duration")
    if not 1 <= ttl_seconds <= _MAX_SESSION_SECONDS:
        raise ValueError("Session duration out of range")
    issued = int(time.time() if now is None else now)
    payload = {
        "uid": user_id,
        "iat": issued,
        "exp": issued + ttl_seconds,
        "nonce": secrets.token_hex(16),
    }
    body = _encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = _encode(_sign(body, secret))
    return body + "." + signature


def verify_session(token, secret, now=None):
    """Return verified claims or None for invalid/expired tokens."""
    try:
        if not isinstance(token, str) or len(token) > 2048:
            return None
        body, signature = token.split(".")
        expected = _sign(body, secret)
        if not hmac.compare_digest(_decode(signature), expected):
            return None
        claims = json.loads(_decode(body))
        current = int(time.time() if now is None else now)
        uid, issued, expiry = claims["uid"], claims["iat"], claims["exp"]
        if any(type(x) is not int for x in (uid, issued, expiry)):
            return None
        if uid <= 0 or issued > current or not issued < expiry:
            return None
        if expiry - issued > _MAX_SESSION_SECONDS or current >= expiry:
            return None
        if not isinstance(claims.get("nonce"), str) or len(claims["nonce"]) != 32:
            return None
        return claims
    except (ValueError, TypeError, KeyError, UnicodeError, OverflowError):
        return None
