"""Database Models and Relational Integrity Tests.

Covers:
1. Table creation and primary key generation.
2. Unique constraints on username and email.
3. Foreign key cascading (deleting a User removes their vault secrets with zero orphans).
4. Audit log entry storage and HMAC signature fields.
"""

import uuid
import pytest
from sqlalchemy import create_engine, select, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.models.database import Base, User, MasterKey, VaultSecret, AuditLog


@pytest.fixture
def db():
    """Create in-memory SQLite database with foreign keys enabled."""
    engine = create_engine("sqlite:///:memory:", echo=False)

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()


class TestDatabaseModels:
    """Test suite for relational integrity and database constraints."""

    def test_user_creation_and_defaults(self, db):
        """User creation sets default role and generates UUID."""
        user = User(
            username="alice_dev",
            email="alice@company.internal",
            password_hash="$argon2id$fake_hash",
        )
        db.add(user)
        db.commit()

        assert user.id is not None
        assert len(user.id) == 36  # UUID string format
        assert user.role == "USER"
        assert user.failed_login_count == 0

    def test_unique_username_constraint(self, db):
        """Duplicate usernames must violate unique constraint."""
        u1 = User(username="samename", email="u1@test.internal", password_hash="h1")
        u2 = User(username="samename", email="u2@test.internal", password_hash="h2")
        db.add(u1)
        db.commit()

        db.add(u2)
        with pytest.raises(IntegrityError):
            db.commit()

    def test_unique_email_constraint(self, db):
        """Duplicate emails must violate unique constraint."""
        u1 = User(username="user1", email="same@test.internal", password_hash="h1")
        u2 = User(username="user2", email="same@test.internal", password_hash="h2")
        db.add(u1)
        db.commit()

        db.add(u2)
        with pytest.raises(IntegrityError):
            db.commit()

    def test_foreign_key_cascade_deletion(self, db):
        """Deleting a User must cascade delete all of their vault secrets."""
        # 1. Create User
        user = User(username="secret_owner", email="owner@test.internal", password_hash="hash")
        db.add(user)

        # 2. Create Master Key
        master_key = MasterKey(
            id="k-master-v1",
            key_name="finance-kek",
            encrypted_key_bytes="wrapped_key_bytes_base64",
            status="ACTIVE",
        )
        db.add(master_key)
        db.commit()

        # 3. Create Secret bound to User and Master Key
        secret = VaultSecret(
            id=str(uuid.uuid4()),
            owner_id=user.id,
            key_id=master_key.id,
            secret_name="StripeAPIKey",
            encrypted_payload="cipher_base64",
            encrypted_dek="dek_base64",
            payload_nonce="p_nonce_base64",
            payload_tag="p_tag_base64",
            dek_nonce="d_nonce_base64",
            dek_tag="d_tag_base64",
        )
        db.add(secret)
        db.commit()

        # Save secret_id before deleting user
        secret_id = secret.id

        # Verify secret exists
        fetched_secret = db.execute(select(VaultSecret).where(VaultSecret.id == secret_id)).scalar_one_or_none()
        assert fetched_secret is not None

        # 4. Delete the User
        db.delete(user)
        db.commit()

        # Verify secret was cascade-deleted (zero orphan records)
        orphan_secret = db.execute(select(VaultSecret).where(VaultSecret.id == secret_id)).scalar_one_or_none()
        assert orphan_secret is None

    def test_audit_log_record_creation(self, db):
        """Audit log records store hash chain and HMAC signatures."""
        log = AuditLog(
            actor_id="user-123",
            action="SECRET_WRITE",
            resource_id="secret-abc",
            previous_record_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            record_hmac="hmac_signature_base64",
        )
        db.add(log)
        db.commit()

        assert log.id is not None
        assert log.action == "SECRET_WRITE"
        assert log.timestamp is not None
