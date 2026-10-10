"""Vault Secret CRUD Endpoints with Two-Tier Envelope Encryption and Anti-IDOR Protection."""

from typing import List
from cryptography.exceptions import InvalidTag
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.api.keys import unwrap_master_kek
from app.core.rbac import Role, can_access_secret
from app.crypto.audit_chain import record_audit_event
from app.crypto.envelope import EnvelopeCryptoEngine
from app.models.database import MasterKey, User, VaultSecret
from app.models.schemas import (
    SecretCreateRequest,
    SecretDetailResponse,
    SecretMetadataResponse,
)

router = APIRouter(prefix="/secrets", tags=["Vault Secrets"])


@router.post(
    "",
    response_model=SecretMetadataResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create and store a secret using Two-Tier Envelope Encryption (User only)",
)
def create_secret(
    req: SecretCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Store secret using transient DEK encrypted with AES-256-GCM and wrapped under Master KEK."""
    # Enforce RBAC: Only standard USER role can create personal secrets
    if current_user.role != Role.USER.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Only standard users can create personal secrets",
        )

    # 1. Select Active Master Key (KEK)
    if req.key_id:
        master_key = db.execute(
            select(MasterKey).where(MasterKey.id == req.key_id, MasterKey.status == "ACTIVE")
        ).scalar_one_or_none()
        if not master_key:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Active Master Key '{req.key_id}' not found",
            )
    else:
        master_key = db.execute(
            select(MasterKey).where(MasterKey.status == "ACTIVE").order_by(MasterKey.created_at.desc()).limit(1)
        ).scalar_one_or_none()
        if not master_key:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="No active Master Key available in system. Administrator must initialize keys.",
            )

    # 2. Unwrap Master KEK
    master_kek = unwrap_master_kek(master_key.encrypted_key_bytes)

    # 3. Generate transient 256-bit symmetric DEK
    transient_dek = EnvelopeCryptoEngine.generate_dek()

    # 4. Encrypt plaintext payload with transient DEK using AES-256-GCM
    payload_envelope = EnvelopeCryptoEngine.encrypt_data(dek=transient_dek, plaintext=req.plaintext)

    # 5. Wrap transient DEK under Master KEK using AES-256-GCM
    dek_envelope = EnvelopeCryptoEngine.wrap_key(kek=master_kek, target_key=transient_dek)

    # 6. Scrub transient plaintext keys from memory
    del transient_dek
    del master_kek

    # 7. Persist zero-plaintext encrypted record to database
    secret_record = VaultSecret(
        owner_id=current_user.id,
        key_id=master_key.id,
        secret_name=req.secret_name,
        encrypted_payload=payload_envelope["ciphertext"],
        payload_nonce=payload_envelope["nonce"],
        payload_tag=payload_envelope["tag"],
        encrypted_dek=dek_envelope["wrapped_key"],
        dek_nonce=dek_envelope["nonce"],
        dek_tag=dek_envelope["tag"],
    )
    db.add(secret_record)
    db.commit()
    db.refresh(secret_record)

    # 8. Cryptographic audit log
    record_audit_event(
        db,
        actor_id=current_user.id,
        action="SECRET_WRITE",
        resource_id=secret_record.id,
    )

    return secret_record


@router.get(
    "",
    response_model=List[SecretMetadataResponse],
    summary="List metadata for all secrets owned by current user (Zero-Knowledge: Admin denied)",
)
def list_secrets(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve metadata of secrets belonging to authenticated user (no plaintext exposed)."""
    # Zero-Knowledge: Admin and Auditor have zero visibility into user secrets
    if current_user.role != Role.USER.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Zero-Knowledge policy denies non-user accounts access to secrets",
        )

    secrets = db.execute(
        select(VaultSecret).where(VaultSecret.owner_id == current_user.id).order_by(VaultSecret.created_at.desc())
    ).scalars().all()

    return secrets


@router.get(
    "/{secret_id}",
    response_model=SecretDetailResponse,
    summary="Decrypt and retrieve a secret payload (Enforces Anti-IDOR and GCM Tag Validation)",
)
def get_secret_detail(
    secret_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Unwrap transient DEK, decrypt payload with AES-256-GCM, and return plaintext."""
    # Zero-Knowledge check
    if current_user.role != Role.USER.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Zero-Knowledge policy denies non-user accounts access to secrets",
        )

    secret = db.execute(
        select(VaultSecret).where(VaultSecret.id == secret_id)
    ).scalar_one_or_none()

    if not secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found",
        )

    # Anti-IDOR ownership validation (Oral Defense Step 2)
    if not can_access_secret(current_user.id, secret.owner_id, current_user.role):
        record_audit_event(
            db,
            actor_id=current_user.id,
            action="IDOR_ATTEMPT_BLOCKED",
            resource_id=secret.id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: you do not have permission to view this secret",
        )

    # Decrypt secret via two-tier unwrap
    try:
        master_kek = unwrap_master_kek(secret.master_key.encrypted_key_bytes)
        dek = EnvelopeCryptoEngine.unwrap_key(
            kek=master_kek,
            b64_wrapped_key=secret.encrypted_dek,
            b64_nonce=secret.dek_nonce,
            b64_tag=secret.dek_tag,
        )
        plaintext_bytes = EnvelopeCryptoEngine.decrypt_data(
            dek=dek,
            b64_ciphertext=secret.encrypted_payload,
            b64_nonce=secret.payload_nonce,
            b64_tag=secret.payload_tag,
        )
        del dek
        del master_kek
    except InvalidTag:
        # Oral Defense Step 3: Direct database bit-tampering triggers InvalidTag
        record_audit_event(
            db,
            actor_id=current_user.id,
            action="TAMPER_DETECT_INTEGRITY_FAIL",
            resource_id=secret.id,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cryptographic integrity verification failed: ciphertext or tag was altered",
        )

    record_audit_event(
        db,
        actor_id=current_user.id,
        action="SECRET_READ",
        resource_id=secret.id,
    )

    return {
        "id": secret.id,
        "secret_name": secret.secret_name,
        "key_id": secret.key_id,
        "plaintext": plaintext_bytes.decode("utf-8"),
        "created_at": secret.created_at,
        "updated_at": secret.updated_at,
    }


@router.delete(
    "/{secret_id}",
    summary="Permanently delete a secret (Anti-IDOR protected)",
)
def delete_secret(
    secret_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a secret permanently with ownership verification."""
    if current_user.role != Role.USER.value:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Zero-Knowledge policy denies non-user accounts access to secrets",
        )

    secret = db.execute(
        select(VaultSecret).where(VaultSecret.id == secret_id)
    ).scalar_one_or_none()

    if not secret:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Secret not found",
        )

    if not can_access_secret(current_user.id, secret.owner_id, current_user.role):
        record_audit_event(
            db,
            actor_id=current_user.id,
            action="IDOR_ATTEMPT_BLOCKED",
            resource_id=secret.id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access forbidden: you do not have permission to delete this secret",
        )

    db.delete(secret)
    db.commit()

    record_audit_event(
        db,
        actor_id=current_user.id,
        action="SECRET_DELETE",
        resource_id=secret_id,
    )

    return {"message": "Secret permanently deleted"}
