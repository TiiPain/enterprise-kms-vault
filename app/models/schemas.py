"""Pydantic Request and Response Schemas for API validation."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field


# -----------------------------------------------------------------------------
# User & Authentication Schemas
# -----------------------------------------------------------------------------

class UserRegisterRequest(BaseModel):
    """Payload for creating a new user account."""

    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_\-\.]+$")
    email: EmailStr
    password: str = Field(..., min_length=12, max_length=128)


class UserLoginRequest(BaseModel):
    """Payload for authenticating a user."""

    username: str
    password: str


class UserResponse(BaseModel):
    """Public user account response (never exposes password hashes or lockout counters)."""

    id: str
    username: str
    email: str
    role: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# -----------------------------------------------------------------------------
# Master Key (KMS KEK) Schemas
# -----------------------------------------------------------------------------

class KeyCreateRequest(BaseModel):
    """Payload for creating a new Master Key (KEK)."""

    key_id: str = Field(..., min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$")
    key_name: str = Field(..., min_length=3, max_length=128)


class KeyResponse(BaseModel):
    """Master Key metadata response (encrypted key bytes not exposed directly)."""

    id: str
    key_name: str
    key_version: int
    status: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# -----------------------------------------------------------------------------
# Vault Secret Schemas
# -----------------------------------------------------------------------------

class SecretCreateRequest(BaseModel):
    """Payload for storing a new envelope-encrypted secret."""

    secret_name: str = Field(..., min_length=1, max_length=255)
    plaintext: str = Field(..., min_length=1)
    key_id: Optional[str] = None


class SecretMetadataResponse(BaseModel):
    """Secret listing response exposing metadata without decrypted plaintext."""

    id: str
    secret_name: str
    key_id: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class SecretDetailResponse(BaseModel):
    """Single secret response including decrypted plaintext payload."""

    id: str
    secret_name: str
    key_id: str
    plaintext: str
    created_at: datetime
    updated_at: datetime


# -----------------------------------------------------------------------------
# Audit Log Schemas
# -----------------------------------------------------------------------------

class AuditLogResponse(BaseModel):
    """Cryptographic audit trail entry."""

    id: int
    actor_id: str
    action: str
    resource_id: Optional[str]
    timestamp: datetime
    previous_record_hash: str
    record_hmac: str

    model_config = ConfigDict(from_attributes=True)
