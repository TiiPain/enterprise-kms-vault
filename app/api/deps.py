"""FastAPI Dependency Injection for Database Sessions and Authentication Guards."""

from typing import Generator, Optional
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.rbac import Role
from app.core.security import is_account_locked, verify_session_token
from app.models.database import SessionLocal, User

# Optional Bearer security scheme for Swagger UI & automated REST tests
security_scheme = HTTPBearer(auto_error=False)


def get_db() -> Generator[Session, None, None]:
    """Dependency that creates and closes an active database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_user(
    request: Request,
    auth_header: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Retrieve the currently authenticated user from secure cookie or Authorization header.

    Enforces session validity and checks if account is locked.
    """
    token: Optional[str] = None

    # 1. Check HttpOnly cookie
    if "session_token" in request.cookies:
        token = request.cookies.get("session_token")

    # 2. Check Bearer Authorization header as fallback
    elif auth_header and auth_header.credentials:
        token = auth_header.credentials

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: missing session token",
        )

    token_data = verify_session_token(token)
    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token",
        )

    user_id, _ = token_data
    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated user no longer exists",
        )

    if is_account_locked(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is currently locked out due to excessive failed login attempts",
        )

    return user


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Authorization guard requiring ADMIN role."""
    if current_user.role != Role.ADMIN.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Administrative privileges required",
        )
    return current_user


def require_auditor_or_admin(current_user: User = Depends(get_current_user)) -> User:
    """Authorization guard requiring AUDITOR or ADMIN role."""
    if current_user.role not in [Role.ADMIN.value, Role.AUDITOR.value]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Auditor or Administrator privileges required",
        )
    return current_user
