"""Tamper-Evident Cryptographic Audit Logging Engine.

Implements immutable audit trails using:
1. Cryptographic SHA-256 hash chaining:
   H_i = SHA-256(H_{i-1} || timestamp || actor_id || action || resource_id)
2. HMAC-SHA256 signature verification using server-side AUDIT_HMAC_SECRET.
3. Verification engine capable of detecting any record modification, insertion, or deletion.
"""

import hashlib
import hmac
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.models.database import AuditLog

GENESIS_HASH: str = "0000000000000000000000000000000000000000000000000000000000000000"


def format_log_string(
    prev_hash: str,
    timestamp_str: str,
    actor_id: str,
    action: str,
    resource_id: Optional[str] = None,
) -> str:
    """Format canonical string representation for cryptographic hashing and signing."""
    res_str = resource_id if resource_id is not None else "NONE"
    return f"{prev_hash}|{timestamp_str}|{actor_id}|{action}|{res_str}"


def compute_chained_hash(
    prev_hash: str,
    timestamp_str: str,
    actor_id: str,
    action: str,
    resource_id: Optional[str] = None,
) -> str:
    """Compute SHA-256 hash chained from the previous record hash."""
    canonical = format_log_string(prev_hash, timestamp_str, actor_id, action, resource_id)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_hmac_signature(secret_key: str, chained_hash: str) -> str:
    """Compute HMAC-SHA256 signature for the chained record hash."""
    return hmac.new(
        secret_key.encode("utf-8"),
        chained_hash.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def record_audit_event(
    db: Session,
    actor_id: str,
    action: str,
    resource_id: Optional[str] = None,
) -> AuditLog:
    """Append a new tamper-evident audit log record to the cryptographic chain.

    Args:
        db: Active SQLAlchemy database session.
        actor_id: UUID or identifier of user/entity initiating the action.
        action: Security event type (e.g., AUTH_LOGIN, SECRET_WRITE, KEY_GEN).
        resource_id: Optional UUID of accessed or modified resource.

    Returns:
        AuditLog: The persisted audit log instance.
    """
    # Retrieve the most recent log record to obtain the previous hash
    last_log = db.execute(
        select(AuditLog).order_by(AuditLog.id.desc()).limit(1)
    ).scalar_one_or_none()

    prev_hash = last_log.previous_record_hash if last_log else GENESIS_HASH

    # ISO-8601 UTC timestamp representation
    now_utc = datetime.now(timezone.utc)
    timestamp_str = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Calculate SHA-256 chained hash and HMAC-SHA256 signature
    current_hash = compute_chained_hash(prev_hash, timestamp_str, actor_id, action, resource_id)
    record_hmac = compute_hmac_signature(settings.AUDIT_HMAC_SECRET, current_hash)

    log_entry = AuditLog(
        actor_id=actor_id,
        action=action,
        resource_id=resource_id,
        timestamp=now_utc,
        previous_record_hash=current_hash,
        record_hmac=record_hmac,
    )

    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry


def verify_audit_chain(db: Session) -> Dict[str, Any]:
    """Verify the integrity of the entire audit trail from genesis to head.

    Validates:
    1. Chained SHA-256 hashes linking every record sequentially.
    2. HMAC-SHA256 signatures for every record.

    Returns:
        Dict[str, Any]:
            - 'valid': bool (True if entire chain is untampered)
            - 'total_records': int
            - 'corrupted_record_id': Optional[int]
            - 'reason': Optional[str]
    """
    records = db.execute(select(AuditLog).order_by(AuditLog.id.asc())).scalars().all()

    if not records:
        return {
            "valid": True,
            "total_records": 0,
            "corrupted_record_id": None,
            "reason": None,
        }

    expected_prev_hash = GENESIS_HASH

    for record in records:
        ts_str = record.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ") if record.timestamp.tzinfo else record.timestamp.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # 1. Verify SHA-256 hash chaining
        expected_hash = compute_chained_hash(
            expected_prev_hash,
            ts_str,
            record.actor_id,
            record.action,
            record.resource_id,
        )

        if not hmac.compare_digest(record.previous_record_hash, expected_hash):
            return {
                "valid": False,
                "total_records": len(records),
                "corrupted_record_id": record.id,
                "reason": f"Hash chain violation at record {record.id}: stored hash does not match computed chained hash.",
            }

        # 2. Verify HMAC-SHA256 signature
        expected_hmac = compute_hmac_signature(settings.AUDIT_HMAC_SECRET, record.previous_record_hash)
        if not hmac.compare_digest(record.record_hmac, expected_hmac):
            return {
                "valid": False,
                "total_records": len(records),
                "corrupted_record_id": record.id,
                "reason": f"HMAC signature verification failed at record {record.id}: record was altered.",
            }

        expected_prev_hash = record.previous_record_hash

    return {
        "valid": True,
        "total_records": len(records),
        "corrupted_record_id": None,
        "reason": None,
    }
