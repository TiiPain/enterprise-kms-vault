"""Defensive Security Controls & Identity Primitives.

Implements:
1. Memory-hard Argon2id password hashing (m=64MB, t=2, p=2) resilient to GPU attacks.
2. Strict password complexity policy enforcement.
3. Account lockout defense locking accounts for 15 minutes after 5 consecutive failed logins.
4. Cryptographically secure session token generation.
"""

import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Tuple
import argon2
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from sqlalchemy.orm import Session

from app.config import settings
from app.models.database import User

# Argon2id hasher configured according to NIST & project specifications (64MB memory cost)
_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=65536,  # 64 MB
    parallelism=2,
    hash_len=32,
    salt_len=16,
    type=argon2.Type.ID,
)


def hash_password(plain_password: str) -> str:
    """Hash plaintext password using memory-hard Argon2id.

    Args:
        plain_password: The user's plaintext password.

    Returns:
        str: Encoded Argon2id hash containing salt, parameters, and digest.
    """
    return _hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against stored Argon2id hash with constant-time comparison.

    Args:
        plain_password: Password attempt supplied by the user.
        hashed_password: Stored Argon2id hash string from database.

    Returns:
        bool: True if password matches, False otherwise.
    """
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError):
        return False
    except Exception:
        return False


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """Validate that password meets enterprise security complexity requirements.

    Requirements:
    - Minimum 12 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 digit
    - At least 1 special symbol

    Returns:
        Tuple[bool, str]: (is_valid, error_message)
    """
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit"
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?~`]", password):
        return False, "Password must contain at least one special character"

    return True, ""


def is_account_locked(user: User) -> bool:
    """Check if an account is currently locked out due to brute-force attempts.

    Args:
        user: Database User record.

    Returns:
        bool: True if account is currently locked, False otherwise.
    """
    if not user.lockout_until:
        return False

    current_time = datetime.now(timezone.utc)
    lockout_time = user.lockout_until

    # Ensure timezone awareness for comparison
    if lockout_time.tzinfo is None:
        lockout_time = lockout_time.replace(tzinfo=timezone.utc)

    if current_time < lockout_time:
        return True

    return False


def record_failed_login(db: Session, user: User) -> bool:
    """Record a failed login attempt and enforce lockout if threshold is exceeded.

    Args:
        db: Active SQLAlchemy database session.
        user: Database User record.

    Returns:
        bool: True if this attempt resulted in a new account lockout, False otherwise.
    """
    user.failed_login_count = (user.failed_login_count or 0) + 1

    if user.failed_login_count >= settings.MAX_LOGIN_ATTEMPTS:
        user.lockout_until = datetime.now(timezone.utc) + timedelta(minutes=settings.LOCKOUT_MINUTES)
        db.commit()
        return True

    db.commit()
    return False


def reset_failed_logins(db: Session, user: User) -> None:
    """Reset failed login counter and lockout timer upon successful authentication."""
    user.failed_login_count = 0
    user.lockout_until = None
    db.commit()


def generate_session_token() -> str:
    """Generate a cryptographically secure 256-bit URL-safe session token."""
    return secrets.token_urlsafe(32)
