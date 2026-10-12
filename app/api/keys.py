"""KMS Master Key (KEK) Management and Key Rotation Endpoints (Admin Only)."""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_admin
from app.config import settings
from app.crypto.audit_chain import record_audit_event
from app.crypto.envelope import EnvelopeCryptoEngine
from app.models.database import MasterKey, User, VaultSecret
from app.models.schemas import KeyCreateRequest, KeyResponse

router = APIRouter(prefix="/keys", tags=["KMS Key Management"])


def serialize_wrapped_key(wrapped: dict) -> str:
    """Serialize wrapped key dict (key:nonce:tag) for storage."""
    return f"{wrapped['wrapped_key']}:{wrapped['nonce']}:{wrapped['tag']}"


def deserialize_wrapped_key(stored_str: str) -> dict:
    """Deserialize stored wrapped key string into components."""
    parts = stored_str.split(":")
    if len(parts) != 3:
        raise ValueError("Invalid serialized wrapped key format")
    return {"wrapped_key": parts[0], "nonce": parts[1], "tag": parts[2]}


def unwrap_master_kek(stored_str: str) -> bytes:
    """Unwrap stored master KEK using the Server Root KEK."""
    components = deserialize_wrapped_key(stored_str)
    root_kek = settings.get_root_kek_bytes()
    return EnvelopeCryptoEngine.unwrap_key(
        kek=root_kek,
        b64_wrapped_key=components["wrapped_key"],
        b64_nonce=components["nonce"],
        b64_tag=components["tag"],
    )


@router.post(
    "",
    response_model=KeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate a new Master Key (KEK) wrapped under Server Root KEK (Admin only)",
)
def create_master_key(
    req: KeyCreateRequest,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Generate a 256-bit Master Key (KEK) and store it wrapped under the Server Root KEK."""
    existing = db.execute(
        select(MasterKey).where(MasterKey.id == req.key_id)
    ).scalar_one_or_none()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Master Key with id '{req.key_id}' already exists",
        )

    # 1. Generate fresh 256-bit symmetric Master Key (KEK)
    raw_kek = EnvelopeCryptoEngine.generate_kek()

    # 2. Wrap KEK under Server Root KEK
    root_kek = settings.get_root_kek_bytes()
    wrapped_envelope = EnvelopeCryptoEngine.wrap_key(kek=root_kek, target_key=raw_kek)
    del raw_kek  # Zero/discard transient plaintext from memory

    # 3. Store record in database
    master_key = MasterKey(
        id=req.key_id,
        key_name=req.key_name,
        key_version=1,
        encrypted_key_bytes=serialize_wrapped_key(wrapped_envelope),
        status="ACTIVE",
    )
    db.add(master_key)
    db.commit()
    db.refresh(master_key)

    # 4. Cryptographic audit log
    record_audit_event(
        db,
        actor_id=current_admin.id,
        action="KEY_GEN",
        resource_id=master_key.id,
    )

    return master_key


@router.get(
    "",
    response_model=List[KeyResponse],
    summary="List all Master Keys metadata (Admin only)",
)
def list_master_keys(
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Retrieve all Master Key records (raw key bytes are never exposed)."""
    keys = db.execute(select(MasterKey).order_by(MasterKey.created_at.desc())).scalars().all()
    return keys


@router.post(
    "/{key_id}/rotate",
    response_model=KeyResponse,
    summary="Rotate a Master Key to a new version (Admin only)",
)
def rotate_master_key(
    key_id: str,
    current_admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """Rotate Master Key by generating a fresh KEK and incrementing key version."""
    master_key = db.execute(
        select(MasterKey).where(MasterKey.id == key_id)
    ).scalar_one_or_none()

    if not master_key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Master Key '{key_id}' not found",
        )

    # 1. Unwrap current (old) Master KEK
    old_master_kek = unwrap_master_kek(master_key.encrypted_key_bytes)

    # 2. Generate new raw KEK
    new_raw_kek = EnvelopeCryptoEngine.generate_kek()

    # 3. Zero-downtime DEK re-wrapping: re-encrypt all existing secret DEKs with the new KEK
    secrets = db.execute(
        select(VaultSecret).where(VaultSecret.key_id == master_key.id)
    ).scalars().all()

    for secret in secrets:
        # Unwrap transient DEK using the old master KEK
        transient_dek = EnvelopeCryptoEngine.unwrap_key(
            kek=old_master_kek,
            b64_wrapped_key=secret.encrypted_dek,
            b64_nonce=secret.dek_nonce,
            b64_tag=secret.dek_tag,
        )
        # Re-wrap transient DEK under the new master KEK
        new_dek_envelope = EnvelopeCryptoEngine.wrap_key(
            kek=new_raw_kek,
            target_key=transient_dek,
        )
        del transient_dek

        secret.encrypted_dek = new_dek_envelope["wrapped_key"]
        secret.dek_nonce = new_dek_envelope["nonce"]
        secret.dek_tag = new_dek_envelope["tag"]

    # 4. Wrap new KEK with Server Root KEK
    root_kek = settings.get_root_kek_bytes()
    wrapped_envelope = EnvelopeCryptoEngine.wrap_key(kek=root_kek, target_key=new_raw_kek)

    del old_master_kek
    del new_raw_kek

    # 5. Persist updated master key and re-wrapped secret DEKs
    master_key.encrypted_key_bytes = serialize_wrapped_key(wrapped_envelope)
    master_key.key_version += 1
    db.commit()
    db.refresh(master_key)

    record_audit_event(
        db,
        actor_id=current_admin.id,
        action="KEY_ROTATE",
        resource_id=master_key.id,
    )

    return master_key
