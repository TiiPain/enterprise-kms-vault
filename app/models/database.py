"""SQLAlchemy Database Engine, Session Management, and Declarative Models.

Enforces strict ACID compliance, relational integrity, and foreign key
constraints on SQLite for cryptographic hash-chaining and zero-orphan data storage.
"""

import uuid
from datetime import datetime
from typing import Generator
from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    event,
    func,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Session
from app.config import settings

# SQLite connection string handling (supports check_same_thread=False for async FastAPI)
connect_args = {"check_same_thread": False} if settings.DATABASE_URL.startswith("sqlite") else {}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    echo=False,
)

# Enforce foreign key constraints in SQLite
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute("PRAGMA foreign_keys=ON")
    except Exception:
        pass
    finally:
        cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class User(Base):
    """User account model with Argon2id hash storage and lockout defense tracking."""

    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(32), nullable=False, default="USER")
    failed_login_count = Column(Integer, nullable=False, default=0)
    lockout_until = Column(DateTime, nullable=True)
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    # Cascade delete to ensure zero orphaned secrets
    secrets = relationship(
        "VaultSecret",
        back_populates="owner",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class MasterKey(Base):
    """Master Key (KEK) record used to wrap transient Data Encryption Keys (DEKs)."""

    __tablename__ = "master_keys"

    id = Column(String(64), primary_key=True)
    key_name = Column(String(128), nullable=False, index=True)
    key_version = Column(Integer, nullable=False, default=1)
    encrypted_key_bytes = Column(Text, nullable=False)  # Wrapped under Root KEK
    status = Column(String(32), nullable=False, default="ACTIVE")  # ACTIVE, ROTATED, DISABLED
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    secrets = relationship("VaultSecret", back_populates="master_key")


class VaultSecret(Base):
    """Encrypted secret record storing envelope ciphertext, nonces, and wrapped DEK."""

    __tablename__ = "vault_secrets"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id = Column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    key_id = Column(
        String(64),
        ForeignKey("master_keys.id"),
        nullable=False,
        index=True,
    )
    secret_name = Column(String(255), nullable=False, index=True)
    encrypted_payload = Column(Text, nullable=False)  # Base64 AES-256-GCM ciphertext
    encrypted_dek = Column(Text, nullable=False)      # Base64 DEK encrypted by KEK
    payload_nonce = Column(String(64), nullable=False) # 12-byte IV in Base64
    payload_tag = Column(String(64), nullable=False)   # 16-byte Auth Tag in Base64
    dek_nonce = Column(String(64), nullable=False)     # 12-byte IV for DEK in Base64
    dek_tag = Column(String(64), nullable=False)       # 16-byte Auth Tag for DEK in Base64
    created_at = Column(DateTime, nullable=False, server_default=func.now())
    updated_at = Column(
        DateTime,
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    owner = relationship("User", back_populates="secrets")
    master_key = relationship("MasterKey", back_populates="secrets")


class AuditLog(Base):
    """Tamper-evident audit log table using SHA-256 chaining and HMAC verification."""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    actor_id = Column(String(64), nullable=False, index=True)
    action = Column(String(64), nullable=False, index=True)
    resource_id = Column(String(64), nullable=True, index=True)
    timestamp = Column(DateTime, nullable=False, server_default=func.now())
    previous_record_hash = Column(String(64), nullable=False)  # SHA-256 hash chain
    record_hmac = Column(String(64), nullable=False)           # HMAC-SHA256 signature


def init_db(target_engine=None):
    """Create all database tables."""
    eng = target_engine or engine
    Base.metadata.create_all(bind=eng)


def get_db() -> Generator[Session, None, None]:
    """Dependency for yielding database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
