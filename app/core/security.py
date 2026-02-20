"""Password hashing and JWT creation/verification for authentication."""

from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
import jwt

from app.core.config import settings

# Bcrypt cost (rounds); 12 is a good default for security vs speed.
BCRYPT_ROUNDS = 12

# Min/max lengths for username and password validation (BSIMM / input validation).
USERNAME_MIN_LEN = 1
USERNAME_MAX_LEN = 255
PASSWORD_MIN_LEN = 8
PASSWORD_MAX_LEN = 128


def hash_password(plain_password: str) -> str:
    """Hash a plain-text password for storage. Do not store plain passwords."""
    # bcrypt has a 72-byte limit; truncate to avoid errors (validation already limits length).
    pw_bytes = plain_password.encode("utf-8")[:72]
    return bcrypt.hashpw(pw_bytes, bcrypt.gensalt(rounds=BCRYPT_ROUNDS)).decode("utf-8")


def verify_password(plain_password: str, hashed: str) -> bool:
    """Verify a plain password against a stored hash."""
    pw_bytes = plain_password.encode("utf-8")[:72]
    try:
        return bcrypt.checkpw(pw_bytes, hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def create_access_token(sub: str | int, role: str) -> str:
    """Create a JWT access token with sub (user id or username), role, and exp."""
    now = datetime.now(UTC)
    expire = now + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    payload: dict[str, Any] = {
        "sub": str(sub),
        "role": role,
        "exp": expire,
        "iat": now,
    }
    secret = settings.JWT_SECRET.get_secret_value()
    return jwt.encode(
        payload,
        secret,
        algorithm=settings.JWT_ALGORITHM,
    )


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decode and validate JWT; return payload (sub, role, exp, iat).
    Raises jwt.PyJWTError on invalid or expired token.
    """
    secret = settings.JWT_SECRET.get_secret_value()
    return jwt.decode(
        token,
        secret,
        algorithms=[settings.JWT_ALGORITHM],
    )
