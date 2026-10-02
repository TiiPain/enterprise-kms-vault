"""Authentication, Identity, and Defensive Lockout Unit Tests.

Covers:
1. Argon2id password hashing parameters and verification.
2. Enterprise password complexity enforcement.
3. Brute-force protection: 5 consecutive failed logins trigger 15-minute account lockout.
4. Account lockout expiration and reset after successful login.
5. Secure session token entropy.
6. Zero-Knowledge RBAC and Anti-IDOR authorization rules.
"""

from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.rbac import Role, can_access_secret, require_role
from app.core.security import (
    generate_session_token,
    hash_password,
    is_account_locked,
    record_failed_login,
    reset_failed_logins,
    validate_password_strength,
    verify_password,
)
from app.models.database import Base, User


@pytest.fixture
def db_session():
    """Create a temporary in-memory database session for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()


class TestPasswordSecurity:
    """Test suite for Argon2id hashing and password validation."""

    def test_argon2id_hash_generation_and_parameters(self):
        """Argon2id hashes must contain correct parameters (m=64MB, t=2, p=2)."""
        password = "P@ssw0rdSecureEnterprise123!"
        hashed = hash_password(password)

        assert isinstance(hashed, str)
        assert hashed.startswith("$argon2id$")
        # Ensure memory cost m=65536 (64MB) and t=2, p=2 are embedded in the hash string
        assert "m=65536,t=2,p=2" in hashed

    def test_argon2id_verification_success(self):
        """Verification of the correct password must return True."""
        password = "CorrectSuperSecretPassword456!"
        hashed = hash_password(password)

        assert verify_password(password, hashed) is True

    def test_argon2id_verification_failure(self):
        """Verification with incorrect password must return False."""
        password = "CorrectPassword123!"
        hashed = hash_password(password)

        assert verify_password("WrongPassword999!", hashed) is False
        assert verify_password("", hashed) is False

    @pytest.mark.parametrize(
        "weak_password, expected_error",
        [
            ("Short1!", "at least 12 characters"),
            ("alllowercasepassword123!", "uppercase letter"),
            ("ALLUPPERCASEPASSWORD123!", "lowercase letter"),
            ("NoDigitsInThisPassword!", "at least one digit"),
            ("NoSpecialCharacters12345", "at least one special character"),
        ],
    )
    def test_password_strength_rejections(self, weak_password, expected_error):
        """Passwords failing complexity rules must be rejected with helpful errors."""
        is_valid, error = validate_password_strength(weak_password)
        assert is_valid is False
        assert expected_error in error

    def test_password_strength_acceptance(self):
        """Passwords meeting all enterprise requirements must be accepted."""
        strong_pass = "Comp1ex&Str0ngPassphrase!2026"
        is_valid, error = validate_password_strength(strong_pass)
        assert is_valid is True
        assert error == ""


class TestBruteForceProtection:
    """Test suite for brute-force rate limiting and 15-minute account lockout."""

    def test_account_lockout_after_five_failed_attempts(self, db_session):
        """Oral Defense Step 4: 5 consecutive failed logins must lock the account for 15 minutes."""
        user = User(
            username="target_victim",
            email="target@enterprise.local",
            password_hash=hash_password("ValidPassword123!"),
            failed_login_count=0,
        )
        db_session.add(user)
        db_session.commit()

        # Attempts 1 to 4: account remains unlocked
        for attempt in range(1, 5):
            newly_locked = record_failed_login(db_session, user)
            assert newly_locked is False
            assert user.failed_login_count == attempt
            assert is_account_locked(user) is False

        # Attempt 5: triggers 15-minute lockout
        newly_locked = record_failed_login(db_session, user)
        assert newly_locked is True
        assert user.failed_login_count == 5
        assert is_account_locked(user) is True
        assert user.lockout_until is not None

        # Lockout duration should be approximately 15 minutes
        remaining_time = user.lockout_until.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)
        assert timedelta(minutes=14) <= remaining_time <= timedelta(minutes=16)

    def test_successful_login_resets_failed_count(self, db_session):
        """A successful authentication must clear failed login attempts and lockout state."""
        user = User(
            username="resettable_user",
            email="reset@enterprise.local",
            password_hash=hash_password("ValidPassword123!"),
            failed_login_count=4,
        )
        db_session.add(user)
        db_session.commit()

        reset_failed_logins(db_session, user)

        assert user.failed_login_count == 0
        assert user.lockout_until is None
        assert is_account_locked(user) is False

    def test_lockout_expiration_unlocks_account(self, db_session):
        """An account with an expired lockout timer must be treated as unlocked."""
        user = User(
            username="expired_lockout_user",
            email="expired@enterprise.local",
            password_hash=hash_password("ValidPassword123!"),
            failed_login_count=5,
            # Set lockout_until in the past (e.g., 5 minutes ago)
            lockout_until=datetime.now(timezone.utc) - timedelta(minutes=5),
        )
        db_session.add(user)
        db_session.commit()

        assert is_account_locked(user) is False


class TestSessionSecurity:
    """Test suite for cryptographically random session tokens."""

    def test_session_token_generation_entropy(self):
        """Tokens must be URL-safe, high entropy, and non-repeating."""
        token1 = generate_session_token()
        token2 = generate_session_token()

        assert isinstance(token1, str)
        assert len(token1) >= 40
        assert token1 != token2


class TestZeroKnowledgeRBAC:
    """Test suite for Zero-Knowledge Access Control and anti-IDOR checks."""

    def test_owner_can_access_own_secret(self):
        """Users can access secrets they created."""
        user_id = "user-uuid-111"
        secret_owner_id = "user-uuid-111"
        assert can_access_secret(user_id, secret_owner_id, Role.USER) is True

    def test_idor_non_owner_access_denied(self):
        """Oral Defense Step 2: Non-owner attempting to access another user's secret is denied."""
        user_id = "user-uuid-attacker"
        secret_owner_id = "user-uuid-victim"
        assert can_access_secret(user_id, secret_owner_id, Role.USER) is False

    def test_zero_knowledge_admin_access_denied(self):
        """Zero-Knowledge principle: Admins CANNOT read or decrypt user secrets."""
        admin_id = "admin-uuid-999"
        secret_owner_id = "user-uuid-victim"
        assert can_access_secret(admin_id, secret_owner_id, Role.ADMIN) is False

    def test_auditor_access_to_secret_denied(self):
        """Auditors cannot read user secrets."""
        auditor_id = "auditor-uuid-555"
        secret_owner_id = "user-uuid-victim"
        assert can_access_secret(auditor_id, secret_owner_id, Role.AUDITOR) is False

    def test_require_role_guard(self):
        """Role guard validates permitted system roles."""
        assert require_role(Role.ADMIN, Role.ADMIN) is True
        assert require_role(Role.USER, Role.ADMIN, Role.AUDITOR) is False
        assert require_role(Role.AUDITOR, Role.ADMIN, Role.AUDITOR) is True
