"""Authentication Endpoints: Registration, Login with Lockout Defense, and Logout."""

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.config import settings
from app.core.security import (
    create_session_token,
    hash_password,
    is_account_locked,
    record_failed_login,
    reset_failed_logins,
    validate_password_strength,
    verify_password,
)
from app.crypto.audit_chain import record_audit_event
from app.models.database import User
from app.models.schemas import UserLoginRequest, UserRegisterRequest, UserResponse

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user with Argon2id password protection",
)
def register_user(req: UserRegisterRequest, db: Session = Depends(get_db)):
    """Create a new user account with strict password complexity validation."""
    # 1. Validate password strength
    is_valid, error_msg = validate_password_strength(req.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password policy violation: {error_msg}",
        )

    # 2. Check duplicate username
    existing_username = db.execute(
        select(User).where(User.username == req.username)
    ).scalar_one_or_none()
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken",
        )

    # 3. Check duplicate email
    existing_email = db.execute(
        select(User).where(User.email == req.email)
    ).scalar_one_or_none()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address already registered",
        )

    # 4. Hash password with memory-hard Argon2id
    pwd_hash = hash_password(req.password)

    new_user = User(
        username=req.username,
        email=req.email,
        password_hash=pwd_hash,
        role="USER",
        failed_login_count=0,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # 5. Cryptographic audit trail
    record_audit_event(
        db,
        actor_id=new_user.id,
        action="USER_REGISTER",
        resource_id=new_user.id,
    )

    return new_user


@router.post(
    "/login",
    summary="Authenticate and receive secure session cookie with brute-force lockout protection",
)
def login_user(req: UserLoginRequest, response: Response, db: Session = Depends(get_db)):
    """Authenticate credentials and issue secure session cookie (locks account after 5 failed tries)."""
    user = db.execute(
        select(User).where(User.username == req.username)
    ).scalar_one_or_none()

    if not user:
        record_audit_event(db, actor_id="GUEST", action="AUTH_FAILED", resource_id=None)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Check if currently locked out
    if is_account_locked(user):
        record_audit_event(db, actor_id=user.id, action="AUTH_BLOCKED_LOCKOUT", resource_id=user.id)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account is temporarily locked due to excessive failed attempts. Locked for {settings.LOCKOUT_MINUTES} minutes.",
        )

    # Verify password with constant-time Argon2id check
    if not verify_password(req.password, user.password_hash):
        newly_locked = record_failed_login(db, user)
        if newly_locked:
            record_audit_event(db, actor_id=user.id, action="ACCOUNT_LOCKOUT", resource_id=user.id)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Account locked! Exceeded {settings.MAX_LOGIN_ATTEMPTS} failed attempts. Locked for {settings.LOCKOUT_MINUTES} minutes.",
            )

        record_audit_event(db, actor_id=user.id, action="AUTH_FAILED", resource_id=user.id)
        remaining = settings.MAX_LOGIN_ATTEMPTS - user.failed_login_count
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid username or password. {remaining} attempt(s) remaining before account lockout.",
        )

    # Success: reset failed attempts
    reset_failed_logins(db, user)

    # Generate tamper-evident session token
    session_token = create_session_token(user.id, user.role)

    # Secure cookie headers: HttpOnly, SameSite=Strict, Secure (if https)
    is_secure = settings.APP_ENV == "production"
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        samesite="strict",
        secure=is_secure,
        max_age=settings.SESSION_EXPIRE_MINUTES * 60,
    )

    record_audit_event(db, actor_id=user.id, action="AUTH_LOGIN", resource_id=user.id)

    return {
        "access_token": session_token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "created_at": user.created_at,
        },
    }


@router.post("/logout", summary="Logout and invalidate session cookie")
def logout_user(
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Clear session cookie and log security audit event."""
    response.delete_cookie(key="session_token")
    record_audit_event(
        db,
        actor_id=current_user.id,
        action="AUTH_LOGOUT",
        resource_id=current_user.id,
    )
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserResponse, summary="Get current authenticated user profile")
def get_me(current_user: User = Depends(get_current_user)):
    """Return profile details for the authenticated user."""
    return current_user
