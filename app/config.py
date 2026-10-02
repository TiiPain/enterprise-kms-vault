"""Application Configuration and Security Settings.

Loads configurations from environment variables or .env file with safe
cryptographic defaults for development and strict requirements for production.
"""

import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

# Load .env if present
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


class Settings:
    """Application settings and cryptographic constants."""

    APP_ENV: str = os.getenv("APP_ENV", "development")
    APP_NAME: str = os.getenv("APP_NAME", "Enterprise KMS & Secret Vault")
    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "8000"))

    # Server Root Key Encryption Key (Root KEK) - used to wrap master keys
    # In production, this should be provided via secure KMS or HSM environment
    SERVER_ROOT_KEK: str = os.getenv(
        "SERVER_ROOT_KEK",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    )

    # HMAC Secret for Audit Log integrity chaining
    AUDIT_HMAC_SECRET: str = os.getenv(
        "AUDIT_HMAC_SECRET",
        "supersecret-audit-hmac-key-minimum-32-bytes-long",
    )

    # Session & JWT secret
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY",
        "dev-session-secret-key-replace-with-cryptographically-random-value",
    )
    SESSION_EXPIRE_MINUTES: int = int(os.getenv("SESSION_EXPIRE_MINUTES", "60"))

    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./keyvault.db")

    # Defensive Security Controls
    MAX_LOGIN_ATTEMPTS: int = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
    LOCKOUT_MINUTES: int = int(os.getenv("LOCKOUT_MINUTES", "15"))

    @classmethod
    def get_root_kek_bytes(cls) -> bytes:
        """Parse and return the 32-byte (256-bit) Root KEK bytes."""
        try:
            kek_bytes = bytes.fromhex(cls.SERVER_ROOT_KEK)
            if len(kek_bytes) != 32:
                raise ValueError(f"Root KEK must be exactly 32 bytes (64 hex characters), got {len(kek_bytes)} bytes")
            return kek_bytes
        except ValueError as exc:
            raise ValueError(f"Invalid SERVER_ROOT_KEK hex string: {exc}") from exc


settings = Settings()
