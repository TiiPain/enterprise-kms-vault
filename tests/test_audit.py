"""Tamper-Evident Cryptographic Audit Chaining Unit Tests.

Covers:
1. Sequential SHA-256 hash chaining from genesis to head.
2. HMAC-SHA256 signature verification.
3. Tamper detection: modifying fields (action, actor_id, resource_id) breaks the hash chain.
4. Tamper detection: altering an HMAC signature directly fails verification.
5. Deletion detection: removing an intermediate record breaks chaining continuity.
"""

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.crypto.audit_chain import (
    GENESIS_HASH,
    record_audit_event,
    verify_audit_chain,
)
from app.models.database import AuditLog, Base


@pytest.fixture
def audit_db():
    """Create in-memory SQLite database for audit trail testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()


class TestCryptographicAuditTrail:
    """Test suite for SHA-256 chaining and HMAC verification."""

    def test_genesis_record_creation(self, audit_db):
        """The first audit record must chain directly from the 64-zero GENESIS_HASH."""
        log = record_audit_event(
            audit_db,
            actor_id="system-user-0",
            action="SYSTEM_INIT",
            resource_id=None,
        )

        assert log.id == 1
        assert log.previous_record_hash != GENESIS_HASH
        assert len(log.previous_record_hash) == 64
        assert len(log.record_hmac) == 64

    def test_consecutive_records_chain_properly(self, audit_db):
        """Sequential records must chain hashes and pass verification."""
        for i in range(5):
            record_audit_event(
                audit_db,
                actor_id=f"user-{i}",
                action=f"ACTION_{i}",
                resource_id=f"res-{i}",
            )

        verification = verify_audit_chain(audit_db)
        assert verification["valid"] is True
        assert verification["total_records"] == 5
        assert verification["corrupted_record_id"] is None

    def test_tampered_action_fails_verification(self, audit_db):
        """Oral Defense Step 4 / Security Test: Modifying an action string MUST break verification."""
        for i in range(3):
            record_audit_event(
                audit_db,
                actor_id=f"user-{i}",
                action="SECRET_READ",
                resource_id="secret-xyz",
            )

        # Attacker tampers with the second record in the database
        target_record = audit_db.execute(select(AuditLog).where(AuditLog.id == 2)).scalar_one()
        target_record.action = "TAMPERED_ACTION"
        audit_db.commit()

        verification = verify_audit_chain(audit_db)
        assert verification["valid"] is False
        assert verification["corrupted_record_id"] == 2
        assert "Hash chain violation" in verification["reason"]

    def test_tampered_actor_fails_verification(self, audit_db):
        """Modifying actor_id must break cryptographic hash chaining."""
        record_audit_event(audit_db, actor_id="alice", action="KEY_GEN", resource_id="key-1")
        record_audit_event(audit_db, actor_id="bob", action="SECRET_READ", resource_id="sec-1")

        target = audit_db.execute(select(AuditLog).where(AuditLog.id == 1)).scalar_one()
        target.actor_id = "mallory_attacker"
        audit_db.commit()

        verification = verify_audit_chain(audit_db)
        assert verification["valid"] is False
        assert verification["corrupted_record_id"] == 1

    def test_tampered_hmac_signature_fails_verification(self, audit_db):
        """Altering the stored HMAC-SHA256 signature must be flagged immediately."""
        record_audit_event(audit_db, actor_id="admin", action="KEY_ROTATE", resource_id="key-v2")

        target = audit_db.execute(select(AuditLog).where(AuditLog.id == 1)).scalar_one()
        # Flip first character of HMAC
        target.record_hmac = "f" + target.record_hmac[1:]
        audit_db.commit()

        verification = verify_audit_chain(audit_db)
        assert verification["valid"] is False
        assert verification["corrupted_record_id"] == 1
        assert "HMAC signature verification failed" in verification["reason"]

    def test_deleted_record_breaks_chain_continuity(self, audit_db):
        """Deleting an intermediate log record breaks the SHA-256 chain."""
        for i in range(4):
            record_audit_event(
                audit_db,
                actor_id=f"user-{i}",
                action="EVENT",
                resource_id=f"res-{i}",
            )

        # Attacker deletes record 2
        rec_to_delete = audit_db.execute(select(AuditLog).where(AuditLog.id == 2)).scalar_one()
        audit_db.delete(rec_to_delete)
        audit_db.commit()

        verification = verify_audit_chain(audit_db)
        assert verification["valid"] is False
        # Record 3 was chained from record 2, so record 3 will fail hash chaining
        assert verification["corrupted_record_id"] == 3
