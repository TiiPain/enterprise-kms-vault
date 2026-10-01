"""Cryptographic Engine Unit Tests.

Covers:
1. DEK and KEK generation (256-bit entropy, uniqueness).
2. Encryption and decryption roundtrips (strings, binary, utf-8, empty, large payloads).
3. Two-Tier Envelope key wrapping and unwrapping (DEK wrapped by KEK).
4. Authenticated Associated Data (AAD) binding and tampering detection.
5. Live Defense Proof: Bit-flipping attack simulation on ciphertext, nonces, and tags (InvalidTag).
6. Nonce collision prevention (AES-GCM non-repeating IVs).
7. Invalid key length and malformed input handling.
"""

import base64
import os
import pytest
from cryptography.exceptions import InvalidTag
from app.crypto.envelope import (
    EnvelopeCryptoEngine,
    KEY_SIZE_BYTES,
    NONCE_SIZE_BYTES,
    TAG_SIZE_BYTES,
)


def flip_base64_bit(b64_string: str) -> str:
    """Helper to flip exactly one bit in a base64-encoded string."""
    raw_bytes = bytearray(base64.b64decode(b64_string))
    # Flip the lowest bit of the first byte
    raw_bytes[0] ^= 0x01
    return base64.b64encode(raw_bytes).decode("utf-8")


class TestEnvelopeCryptoEngine:
    """Test suite for Two-Tier Envelope Cryptography Engine."""

    def test_dek_generation_attributes(self):
        """DEK must be exactly 32 bytes (256 bits) and cryptographically random."""
        dek1 = EnvelopeCryptoEngine.generate_dek()
        dek2 = EnvelopeCryptoEngine.generate_dek()

        assert isinstance(dek1, bytes)
        assert len(dek1) == KEY_SIZE_BYTES
        assert len(dek2) == KEY_SIZE_BYTES
        assert dek1 != dek2, "Successive DEK generations must never collide"

    def test_kek_generation_attributes(self):
        """KEK must be exactly 32 bytes (256 bits) and cryptographically random."""
        kek1 = EnvelopeCryptoEngine.generate_kek()
        kek2 = EnvelopeCryptoEngine.generate_kek()

        assert isinstance(kek1, bytes)
        assert len(kek1) == KEY_SIZE_BYTES
        assert len(kek2) == KEY_SIZE_BYTES
        assert kek1 != kek2, "Successive KEK generations must never collide"

    @pytest.mark.parametrize(
        "payload",
        [
            "SuperSecretPassword123!",
            "DatabaseConnectionString: postgresql://admin:p@ss@db:5432/kms",
            "Special characters: éàçüö$€£¥§!#%&*()[]{}<>?~`±@^/\\|",
            "Emojis: 🔐🛡️⚡🔑🚀",
            "",  # Empty payload edge case
            "A" * 100_000,  # 100 KB payload
            b"Binary\x00\xff\xfe\x01\x02\x03\x7f\x80Payload",
        ],
        ids=[
            "simple_password",
            "db_connection_url",
            "special_characters",
            "emojis",
            "empty_payload",
            "large_100kb_payload",
            "binary_payload",
        ],
    )
    def test_payload_encryption_decryption_roundtrip(self, payload):
        """Plaintext encrypted with DEK must decrypt back to exact original content."""
        dek = EnvelopeCryptoEngine.generate_dek()
        envelope = EnvelopeCryptoEngine.encrypt_data(dek, payload)

        assert "ciphertext" in envelope
        assert "nonce" in envelope
        assert "tag" in envelope

        decrypted_bytes = EnvelopeCryptoEngine.decrypt_data(
            dek=dek,
            b64_ciphertext=envelope["ciphertext"],
            b64_nonce=envelope["nonce"],
            b64_tag=envelope["tag"],
        )

        expected_bytes = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
        assert decrypted_bytes == expected_bytes

    def test_kek_wrap_unwrap_roundtrip(self):
        """Transient DEK wrapped under Master KEK must unwrap back to exact DEK bytes."""
        kek = EnvelopeCryptoEngine.generate_kek()
        dek = EnvelopeCryptoEngine.generate_dek()

        wrapped_envelope = EnvelopeCryptoEngine.wrap_key(kek=kek, target_key=dek)

        assert "wrapped_key" in wrapped_envelope
        assert "nonce" in wrapped_envelope
        assert "tag" in wrapped_envelope

        unwrapped_dek = EnvelopeCryptoEngine.unwrap_key(
            kek=kek,
            b64_wrapped_key=wrapped_envelope["wrapped_key"],
            b64_nonce=wrapped_envelope["nonce"],
            b64_tag=wrapped_envelope["tag"],
        )

        assert unwrapped_dek == dek
        assert len(unwrapped_dek) == KEY_SIZE_BYTES

    def test_full_envelope_two_tier_lifecycle(self):
        """Simulate full KMS lifecycle: Secret -> Transient DEK -> KEK Wrap -> Unpack -> Decrypt."""
        secret_plaintext = "API_KEY_LIVE_99887766554433221100"
        kek = EnvelopeCryptoEngine.generate_kek()

        # Step 1: Generate transient DEK
        dek = EnvelopeCryptoEngine.generate_dek()

        # Step 2: Encrypt secret with DEK
        payload_record = EnvelopeCryptoEngine.encrypt_data(dek, secret_plaintext)

        # Step 3: Wrap DEK under KEK
        wrapped_record = EnvelopeCryptoEngine.wrap_key(kek, dek)

        # Step 4: Transient DEK is discarded from memory (simulated)
        del dek

        # Step 5: Later, unwrap DEK using KEK
        recovered_dek = EnvelopeCryptoEngine.unwrap_key(
            kek=kek,
            b64_wrapped_key=wrapped_record["wrapped_key"],
            b64_nonce=wrapped_record["nonce"],
            b64_tag=wrapped_record["tag"],
        )

        # Step 6: Decrypt secret using recovered DEK
        decrypted_secret = EnvelopeCryptoEngine.decrypt_data(
            dek=recovered_dek,
            b64_ciphertext=payload_record["ciphertext"],
            b64_nonce=payload_record["nonce"],
            b64_tag=payload_record["tag"],
        ).decode("utf-8")

        assert decrypted_secret == secret_plaintext

    # -------------------------------------------------------------------------
    # Tampering and integrity tests
    # -------------------------------------------------------------------------

    def test_bit_flipping_ciphertext_tampering_triggers_invalid_tag(self):
        """Single-bit alteration in ciphertext must raise InvalidTag."""
        dek = EnvelopeCryptoEngine.generate_dek()
        envelope = EnvelopeCryptoEngine.encrypt_data(dek, "Confidential Financial Data")

        tampered_ciphertext = flip_base64_bit(envelope["ciphertext"])

        with pytest.raises(InvalidTag):
            EnvelopeCryptoEngine.decrypt_data(
                dek=dek,
                b64_ciphertext=tampered_ciphertext,
                b64_nonce=envelope["nonce"],
                b64_tag=envelope["tag"],
            )

    def test_nonce_tampering_triggers_invalid_tag(self):
        """Tampering with the 96-bit nonce MUST fail authentication tag verification."""
        dek = EnvelopeCryptoEngine.generate_dek()
        envelope = EnvelopeCryptoEngine.encrypt_data(dek, "Sensitive Operational Secret")

        tampered_nonce = flip_base64_bit(envelope["nonce"])

        with pytest.raises(InvalidTag):
            EnvelopeCryptoEngine.decrypt_data(
                dek=dek,
                b64_ciphertext=envelope["ciphertext"],
                b64_nonce=tampered_nonce,
                b64_tag=envelope["tag"],
            )

    def test_tag_tampering_triggers_invalid_tag(self):
        """Tampering with the 128-bit authentication tag MUST raise InvalidTag."""
        dek = EnvelopeCryptoEngine.generate_dek()
        envelope = EnvelopeCryptoEngine.encrypt_data(dek, "Classified Blueprint")

        tampered_tag = flip_base64_bit(envelope["tag"])

        with pytest.raises(InvalidTag):
            EnvelopeCryptoEngine.decrypt_data(
                dek=dek,
                b64_ciphertext=envelope["ciphertext"],
                b64_nonce=envelope["nonce"],
                b64_tag=tampered_tag,
            )

    def test_wrapped_key_tampering_triggers_invalid_tag(self):
        """Tampering with the wrapped DEK payload MUST fail KEK unwrapping."""
        kek = EnvelopeCryptoEngine.generate_kek()
        dek = EnvelopeCryptoEngine.generate_dek()
        wrapped = EnvelopeCryptoEngine.wrap_key(kek, dek)

        tampered_wrapped_key = flip_base64_bit(wrapped["wrapped_key"])

        with pytest.raises(InvalidTag):
            EnvelopeCryptoEngine.unwrap_key(
                kek=kek,
                b64_wrapped_key=tampered_wrapped_key,
                b64_nonce=wrapped["nonce"],
                b64_tag=wrapped["tag"],
            )

    def test_wrapped_key_tag_tampering_triggers_invalid_tag(self):
        """Tampering with the wrapped DEK tag MUST fail KEK unwrapping."""
        kek = EnvelopeCryptoEngine.generate_kek()
        dek = EnvelopeCryptoEngine.generate_dek()
        wrapped = EnvelopeCryptoEngine.wrap_key(kek, dek)

        tampered_tag = flip_base64_bit(wrapped["tag"])

        with pytest.raises(InvalidTag):
            EnvelopeCryptoEngine.unwrap_key(
                kek=kek,
                b64_wrapped_key=wrapped["wrapped_key"],
                b64_nonce=wrapped["nonce"],
                b64_tag=tampered_tag,
            )

    def test_wrong_dek_fails_decryption(self):
        """Attempting to decrypt ciphertext with a different DEK MUST raise InvalidTag."""
        dek_correct = EnvelopeCryptoEngine.generate_dek()
        dek_wrong = EnvelopeCryptoEngine.generate_dek()
        envelope = EnvelopeCryptoEngine.encrypt_data(dek_correct, "Target Data")

        with pytest.raises(InvalidTag):
            EnvelopeCryptoEngine.decrypt_data(
                dek=dek_wrong,
                b64_ciphertext=envelope["ciphertext"],
                b64_nonce=envelope["nonce"],
                b64_tag=envelope["tag"],
            )

    def test_wrong_kek_fails_unwrapping(self):
        """Attempting to unwrap DEK with wrong KEK MUST raise InvalidTag."""
        kek_correct = EnvelopeCryptoEngine.generate_kek()
        kek_wrong = EnvelopeCryptoEngine.generate_kek()
        dek = EnvelopeCryptoEngine.generate_dek()
        wrapped = EnvelopeCryptoEngine.wrap_key(kek_correct, dek)

        with pytest.raises(InvalidTag):
            EnvelopeCryptoEngine.unwrap_key(
                kek=kek_wrong,
                b64_wrapped_key=wrapped["wrapped_key"],
                b64_nonce=wrapped["nonce"],
                b64_tag=wrapped["tag"],
            )

    # -------------------------------------------------------------------------
    # Nonce uniqueness tests
    # -------------------------------------------------------------------------

    def test_nonce_uniqueness_across_multiple_encryptions(self):
        """Encrypting the exact same plaintext 100 times must yield 100 unique nonces & ciphertexts."""
        dek = EnvelopeCryptoEngine.generate_dek()
        identical_payload = "FixedStaticPayloadValue123456"

        nonces = set()
        ciphertexts = set()

        for _ in range(100):
            res = EnvelopeCryptoEngine.encrypt_data(dek, identical_payload)
            nonces.add(res["nonce"])
            ciphertexts.add(res["ciphertext"])

        assert len(nonces) == 100, "Nonces must never collide or repeat"
        assert len(ciphertexts) == 100, "Ciphertexts must vary due to random nonces"

    # -------------------------------------------------------------------------
    # AUTHENTICATED ASSOCIATED DATA (AAD) TESTS
    # -------------------------------------------------------------------------

    def test_associated_data_binding(self):
        """Authenticated Associated Data (AAD) must match during decryption."""
        dek = EnvelopeCryptoEngine.generate_dek()
        payload = "Confidential Records"
        owner_aad = b"owner:user-uuid-1234;purpose:finance"

        # Encrypt with AAD bound to ciphertext
        envelope = EnvelopeCryptoEngine.encrypt_data(dek, payload, associated_data=owner_aad)

        # Decrypt with correct AAD succeeds
        decrypted = EnvelopeCryptoEngine.decrypt_data(
            dek=dek,
            b64_ciphertext=envelope["ciphertext"],
            b64_nonce=envelope["nonce"],
            b64_tag=envelope["tag"],
            associated_data=owner_aad,
        )
        assert decrypted.decode("utf-8") == payload

        # Decrypt with altered AAD fails
        tampered_aad = b"owner:user-uuid-9999;purpose:finance"
        with pytest.raises(InvalidTag):
            EnvelopeCryptoEngine.decrypt_data(
                dek=dek,
                b64_ciphertext=envelope["ciphertext"],
                b64_nonce=envelope["nonce"],
                b64_tag=envelope["tag"],
                associated_data=tampered_aad,
            )

        # Decrypt with omitted AAD fails
        with pytest.raises(InvalidTag):
            EnvelopeCryptoEngine.decrypt_data(
                dek=dek,
                b64_ciphertext=envelope["ciphertext"],
                b64_nonce=envelope["nonce"],
                b64_tag=envelope["tag"],
                associated_data=None,
            )

    # -------------------------------------------------------------------------
    # INPUT VALIDATION & ERROR HANDLING TESTS
    # -------------------------------------------------------------------------

    @pytest.mark.parametrize("invalid_key", [b"", b"short_key_16_by!", b"x" * 31, b"x" * 33, b"x" * 64])
    def test_invalid_dek_length_raises_value_error(self, invalid_key):
        """DEKs not exactly 32 bytes must immediately be rejected."""
        with pytest.raises(ValueError, match="DEK must be 32 bytes"):
            EnvelopeCryptoEngine.encrypt_data(invalid_key, "data")

        with pytest.raises(ValueError, match="DEK must be 32 bytes"):
            EnvelopeCryptoEngine.decrypt_data(
                invalid_key,
                b64_ciphertext="AAAA",
                b64_nonce="AAAA",
                b64_tag="AAAA",
            )

    @pytest.mark.parametrize("invalid_key", [b"", b"short_key_16_by!", b"x" * 31, b"x" * 33])
    def test_invalid_kek_length_raises_value_error(self, invalid_key):
        """KEKs not exactly 32 bytes must immediately be rejected."""
        valid_dek = EnvelopeCryptoEngine.generate_dek()
        with pytest.raises(ValueError, match="KEK must be 32 bytes"):
            EnvelopeCryptoEngine.wrap_key(kek=invalid_key, target_key=valid_dek)

        with pytest.raises(ValueError, match="KEK must be 32 bytes"):
            EnvelopeCryptoEngine.unwrap_key(
                kek=invalid_key,
                b64_wrapped_key="AAAA",
                b64_nonce="AAAA",
                b64_tag="AAAA",
            )

    def test_corrupted_base64_raises_value_error(self):
        """Malformed base64 characters must raise ValueError."""
        dek = EnvelopeCryptoEngine.generate_dek()
        with pytest.raises(ValueError, match="Corrupted base64"):
            EnvelopeCryptoEngine.decrypt_data(
                dek=dek,
                b64_ciphertext="not-valid-base64-!!!@@@",
                b64_nonce="AAAA",
                b64_tag="AAAA",
            )

    def test_invalid_nonce_length_raises_value_error(self):
        """Nonce decoded to non-12 bytes must raise ValueError."""
        dek = EnvelopeCryptoEngine.generate_dek()
        envelope = EnvelopeCryptoEngine.encrypt_data(dek, "test")
        short_nonce = base64.b64encode(b"short").decode("utf-8")

        with pytest.raises(ValueError, match="Invalid nonce length"):
            EnvelopeCryptoEngine.decrypt_data(
                dek=dek,
                b64_ciphertext=envelope["ciphertext"],
                b64_nonce=short_nonce,
                b64_tag=envelope["tag"],
            )

    def test_invalid_tag_length_raises_value_error(self):
        """Tag decoded to non-16 bytes must raise ValueError."""
        dek = EnvelopeCryptoEngine.generate_dek()
        envelope = EnvelopeCryptoEngine.encrypt_data(dek, "test")
        short_tag = base64.b64encode(b"short_tag").decode("utf-8")

        with pytest.raises(ValueError, match="Invalid authentication tag length"):
            EnvelopeCryptoEngine.decrypt_data(
                dek=dek,
                b64_ciphertext=envelope["ciphertext"],
                b64_nonce=envelope["nonce"],
                b64_tag=short_tag,
            )
