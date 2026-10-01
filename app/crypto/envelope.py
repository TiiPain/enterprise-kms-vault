"""Two-Tier Envelope Cryptographic Engine.

This module provides authenticated encryption and key wrapping primitives
following NIST and industry standards (AWS KMS / HashiCorp Vault patterns).

Key Principles:
1. Two-Tier Envelope Architecture:
   - Plaintext payloads are encrypted with a transient 256-bit Data Encryption Key (DEK).
   - The DEK is encrypted (wrapped) using the Master Key / Key Encryption Key (KEK).
   - Plaintext DEKs are never persisted to disk.
2. Authenticated Encryption with Associated Data (AEAD):
   - Uses AES-256-GCM.
   - Nonces: Cryptographically random 96-bit (12-byte) unique IVs per operation.
   - Authentication Tags: 128-bit (16-byte) tags verifying confidentiality and integrity.
3. Defensive Integrity & Anti-Tamper:
   - Any modification to ciphertext, nonce, or tag strictly raises InvalidTag.
"""

import base64
import os
from typing import Dict, Optional, Union
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE_BYTES: int = 32      # 256 bits
NONCE_SIZE_BYTES: int = 12    # 96 bits (standard for AES-GCM)
TAG_SIZE_BYTES: int = 16      # 128 bits


class EnvelopeCryptoEngine:
    """Core cryptographic engine for transient DEK envelope encryption and KEK wrapping."""

    @staticmethod
    def generate_dek() -> bytes:
        """Generate a cryptographically secure transient 256-bit Data Encryption Key (DEK).

        Returns:
            bytes: 32 raw random bytes suitable for AES-256-GCM.
        """
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def generate_kek() -> bytes:
        """Generate a cryptographically secure 256-bit Master Key / Key Encryption Key (KEK).

        Returns:
            bytes: 32 raw random bytes suitable for AES-256-GCM.
        """
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def encrypt_data(
        dek: bytes,
        plaintext: Union[bytes, str],
        associated_data: Optional[bytes] = None,
    ) -> Dict[str, str]:
        """Encrypt plaintext payload using a transient DEK via AES-256-GCM.

        Generates a fresh 96-bit random nonce for every invocation to ensure
        replay prevention and protect against AES-GCM nonce-reuse attacks.

        Args:
            dek: 32-byte (256-bit) Data Encryption Key.
            plaintext: Plaintext bytes or UTF-8 string to encrypt.
            associated_data: Optional authenticated data (AAD) bound to the ciphertext.

        Returns:
            Dict[str, str]: Base64-encoded strings:
                - 'ciphertext': Raw ciphertext (excluding tag).
                - 'nonce': 12-byte initialization vector.
                - 'tag': 16-byte authentication tag.

        Raises:
            ValueError: If DEK length is not 32 bytes.
        """
        if not isinstance(dek, (bytes, bytearray)) or len(dek) != KEY_SIZE_BYTES:
            raise ValueError(f"DEK must be {KEY_SIZE_BYTES} bytes (256 bits), got {len(dek) if hasattr(dek, '__len__') else type(dek)}")

        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode("utf-8")
        elif isinstance(plaintext, (bytes, bytearray)):
            plaintext_bytes = bytes(plaintext)
        else:
            raise TypeError(f"Plaintext must be bytes or str, got {type(plaintext).__name__}")

        aesgcm = AESGCM(bytes(dek))
        nonce = os.urandom(NONCE_SIZE_BYTES)
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, associated_data)

        ciphertext = ciphertext_with_tag[:-TAG_SIZE_BYTES]
        tag = ciphertext_with_tag[-TAG_SIZE_BYTES:]

        return {
            "ciphertext": base64.b64encode(ciphertext).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "tag": base64.b64encode(tag).decode("utf-8"),
        }

    @staticmethod
    def decrypt_data(
        dek: bytes,
        b64_ciphertext: str,
        b64_nonce: str,
        b64_tag: str,
        associated_data: Optional[bytes] = None,
    ) -> bytes:
        """Decrypt payload and verify authentication tag using AES-256-GCM.

        Args:
            dek: 32-byte (256-bit) Data Encryption Key.
            b64_ciphertext: Base64-encoded ciphertext.
            b64_nonce: Base64-encoded 12-byte nonce.
            b64_tag: Base64-encoded 16-byte authentication tag.
            associated_data: Optional authenticated data (AAD) checked against the tag.

        Returns:
            bytes: Decrypted plaintext payload.

        Raises:
            InvalidTag: If ciphertext, nonce, tag, or associated data was altered,
                        or if an incorrect key was used.
            ValueError: If key, nonce, or tag format/length is invalid.
        """
        if not isinstance(dek, (bytes, bytearray)) or len(dek) != KEY_SIZE_BYTES:
            raise ValueError(f"DEK must be {KEY_SIZE_BYTES} bytes (256 bits), got {len(dek) if hasattr(dek, '__len__') else type(dek)}")

        try:
            ciphertext = base64.b64decode(b64_ciphertext, validate=True)
            nonce = base64.b64decode(b64_nonce, validate=True)
            tag = base64.b64decode(b64_tag, validate=True)
        except Exception as exc:
            raise ValueError(f"Corrupted base64 encoding: {exc}") from exc

        if len(nonce) != NONCE_SIZE_BYTES:
            raise ValueError(f"Invalid nonce length: expected {NONCE_SIZE_BYTES} bytes, got {len(nonce)}")
        if len(tag) != TAG_SIZE_BYTES:
            raise ValueError(f"Invalid authentication tag length: expected {TAG_SIZE_BYTES} bytes, got {len(tag)}")

        aesgcm = AESGCM(bytes(dek))
        return aesgcm.decrypt(nonce, ciphertext + tag, associated_data)

    @staticmethod
    def wrap_key(kek: bytes, target_key: bytes) -> Dict[str, str]:
        """Wrap (encrypt) a transient DEK under the Master Key (KEK) using AES-256-GCM.

        Args:
            kek: 32-byte (256-bit) Master Key / Key Encryption Key.
            target_key: 32-byte (256-bit) target key to wrap (transient DEK).

        Returns:
            Dict[str, str]: Base64-encoded wrapped key, nonce, and tag:
                - 'wrapped_key': Base64 encrypted key bytes.
                - 'nonce': Base64 12-byte initialization vector.
                - 'tag': Base64 16-byte authentication tag.

        Raises:
            ValueError: If KEK or target key is not 32 bytes.
        """
        if not isinstance(kek, (bytes, bytearray)) or len(kek) != KEY_SIZE_BYTES:
            raise ValueError(f"KEK must be {KEY_SIZE_BYTES} bytes (256 bits), got {len(kek) if hasattr(kek, '__len__') else type(kek)}")
        if not isinstance(target_key, (bytes, bytearray)) or len(target_key) != KEY_SIZE_BYTES:
            raise ValueError(f"Target key must be {KEY_SIZE_BYTES} bytes (256 bits), got {len(target_key) if hasattr(target_key, '__len__') else type(target_key)}")

        aesgcm = AESGCM(bytes(kek))
        nonce = os.urandom(NONCE_SIZE_BYTES)
        wrapped_with_tag = aesgcm.encrypt(nonce, bytes(target_key), None)

        wrapped_key = wrapped_with_tag[:-TAG_SIZE_BYTES]
        tag = wrapped_with_tag[-TAG_SIZE_BYTES:]

        return {
            "wrapped_key": base64.b64encode(wrapped_key).decode("utf-8"),
            "nonce": base64.b64encode(nonce).decode("utf-8"),
            "tag": base64.b64encode(tag).decode("utf-8"),
        }

    @staticmethod
    def unwrap_key(kek: bytes, b64_wrapped_key: str, b64_nonce: str, b64_tag: str) -> bytes:
        """Unwrap (decrypt) an encrypted DEK using the Master Key (KEK) via AES-256-GCM.

        Args:
            kek: 32-byte (256-bit) Master Key / Key Encryption Key.
            b64_wrapped_key: Base64-encoded wrapped key bytes.
            b64_nonce: Base64-encoded 12-byte nonce.
            b64_tag: Base64-encoded 16-byte authentication tag.

        Returns:
            bytes: Unwrapped 32-byte Data Encryption Key (DEK).

        Raises:
            InvalidTag: If wrapped key, nonce, or tag was tampered with, or if incorrect KEK was used.
            ValueError: If lengths or encodings are invalid.
        """
        if not isinstance(kek, (bytes, bytearray)) or len(kek) != KEY_SIZE_BYTES:
            raise ValueError(f"KEK must be {KEY_SIZE_BYTES} bytes (256 bits), got {len(kek) if hasattr(kek, '__len__') else type(kek)}")

        try:
            wrapped_key = base64.b64decode(b64_wrapped_key, validate=True)
            nonce = base64.b64decode(b64_nonce, validate=True)
            tag = base64.b64decode(b64_tag, validate=True)
        except Exception as exc:
            raise ValueError(f"Corrupted base64 encoding: {exc}") from exc

        if len(nonce) != NONCE_SIZE_BYTES:
            raise ValueError(f"Invalid nonce length: expected {NONCE_SIZE_BYTES} bytes, got {len(nonce)}")
        if len(tag) != TAG_SIZE_BYTES:
            raise ValueError(f"Invalid authentication tag length: expected {TAG_SIZE_BYTES} bytes, got {len(tag)}")

        aesgcm = AESGCM(bytes(kek))
        unwrapped = aesgcm.decrypt(nonce, wrapped_key + tag, None)

        if len(unwrapped) != KEY_SIZE_BYTES:
            raise ValueError(f"Unwrapped key length error: expected {KEY_SIZE_BYTES} bytes, got {len(unwrapped)}")

        return unwrapped
