"""Audit Trail Endpoints: Inspection and Cryptographic Verification (Admin & Auditor)."""

from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_auditor_or_admin
from app.crypto.audit_chain import verify_audit_chain
from app.models.database import AuditLog, User
from app.models.schemas import AuditLogResponse

router = APIRouter(prefix="/audit", tags=["Cryptographic Audit Trail"])


@router.get(
    "/logs",
    response_model=List[AuditLogResponse],
    summary="View HMAC-signed security and access audit logs (Admin & Auditor only)",
)
def get_audit_logs(
    current_officer: User = Depends(require_auditor_or_admin),
    db: Session = Depends(get_db),
):
    """Retrieve chronologically chained cryptographic audit log records."""
    logs = db.execute(select(AuditLog).order_by(AuditLog.id.asc())).scalars().all()
    return logs


@router.post(
    "/verify",
    summary="Verify cryptographic SHA-256 hash chaining and HMAC signatures (Admin & Auditor only)",
)
def verify_audit_integrity(
    current_officer: User = Depends(require_auditor_or_admin),
    db: Session = Depends(get_db),
):
    """Verify integrity of all records from genesis to head, detecting any tamper attempts."""
    result = verify_audit_chain(db)
    return result
