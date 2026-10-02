"""Role-Based Access Control (RBAC) and Zero-Knowledge Authorization Guards.

Enforces:
1. Strict Object-Level Ownership: Users can only view and manage their own secrets (Anti-IDOR).
2. Zero-Knowledge Admin Principle: Administrators have key lifecycle and audit visibility,
   but CANNOT decrypt or read user secret payloads.
3. Separation of Duties: Auditors can verify cryptographic audit trails without secret access.
"""

from enum import Enum
from typing import Optional


class Role(str, Enum):
    """System authorization roles."""

    USER = "USER"
    AUDITOR = "AUDITOR"
    ADMIN = "ADMIN"


def can_access_secret(user_id: str, secret_owner_id: str, user_role: str) -> bool:
    """Verify if a user is permitted to retrieve or decrypt a specific secret.

    Enforces the Zero-Knowledge principle:
    - Only the secret's creator (owner_id == user_id) is allowed access.
    - Even an ADMIN is strictly denied (Zero-Knowledge model).
    - Non-owners are denied (prevents IDOR / BOLA attacks).

    Args:
        user_id: The authenticated user's ID.
        secret_owner_id: The secret record's owner_id.
        user_role: The authenticated user's assigned role.

    Returns:
        bool: True if authorized, False otherwise.
    """
    if user_role == Role.ADMIN or user_role == Role.AUDITOR:
        # Zero-Knowledge: Admin and Auditor cannot read user secrets
        return False

    return user_id == secret_owner_id


def require_role(user_role: str, *allowed_roles: Role) -> bool:
    """Verify that a user possesses one of the allowed roles for an administrative endpoint."""
    allowed_str_values = [r.value if isinstance(r, Role) else str(r) for r in allowed_roles]
    return user_role in allowed_str_values
