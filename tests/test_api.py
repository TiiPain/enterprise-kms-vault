"""End-to-End REST API Integration Tests.

Covers:
1. Registration & Login (Argon2id, cookie issuance, brute-force lockout defense).
2. Two-Tier Envelope Secret creation, retrieval, and decryption.
3. Anti-IDOR enforcement (User B blocked from accessing User A's secrets).
4. Zero-Knowledge Admin enforcement (Administrators denied from reading secrets).
5. Live Defense Demonstration: Bit-tampering in database ciphertext triggers HTTP 400 InvalidTag.
6. Audit log inspection and cryptographic chain verification.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db
from app.api.keys import serialize_wrapped_key
from app.config import settings
from app.core.security import hash_password
from app.crypto.envelope import EnvelopeCryptoEngine
from app.main import app
from app.models.database import Base, MasterKey, User, VaultSecret


# Shared in-memory engine with StaticPool so all connections share the same memory DB
test_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def setup_test_db():
    """Reset and seed in-memory database for every test."""
    Base.metadata.drop_all(bind=test_engine)
    Base.metadata.create_all(bind=test_engine)

    # Seed root master key
    db = TestingSessionLocal()
    raw_kek = EnvelopeCryptoEngine.generate_kek()
    root_kek = settings.get_root_kek_bytes()
    wrapped_envelope = EnvelopeCryptoEngine.wrap_key(kek=root_kek, target_key=raw_kek)

    master_key = MasterKey(
        id="k-test-root-v1",
        key_name="test-root-kek",
        key_version=1,
        encrypted_key_bytes=serialize_wrapped_key(wrapped_envelope),
        status="ACTIVE",
    )
    db.add(master_key)

    # Seed an Admin and an Auditor
    admin = User(
        username="superadmin",
        email="admin@enterprise.local",
        password_hash=hash_password("AdminSecurePassword123!"),
        role="ADMIN",
    )
    auditor = User(
        username="security_auditor",
        email="auditor@enterprise.local",
        password_hash=hash_password("AuditorSecurePassword123!"),
        role="AUDITOR",
    )
    db.add(admin)
    db.add(auditor)
    db.commit()
    db.close()
    yield


@pytest.fixture
def client():
    """Create FastAPI test client."""
    return TestClient(app)


class TestAPIAuthentication:
    """Authentication and session handling tests."""

    def test_registration_success(self, client):
        """Registering with strong password creates user and returns 201."""
        res = client.post(
            "/api/v1/auth/register",
            json={
                "username": "charlie_engineer",
                "email": "charlie@enterprise.local",
                "password": "StrongPassword!2026",
            },
        )
        assert res.status_code == 201
        data = res.json()
        assert data["username"] == "charlie_engineer"
        assert data["role"] == "USER"

    def test_registration_weak_password_rejected(self, client):
        """Weak passwords must be rejected with 400 Bad Request."""
        res = client.post(
            "/api/v1/auth/register",
            json={
                "username": "weak_user",
                "email": "weak@enterprise.local",
                "password": "simple",
            },
        )
        assert res.status_code == 422 or res.status_code == 400

    def test_login_success_and_cookie_issuance(self, client):
        """Successful login returns session token and sets HttpOnly cookie."""
        # 1. Register
        client.post(
            "/api/v1/auth/register",
            json={
                "username": "alice",
                "email": "alice@enterprise.local",
                "password": "AlicePassword!123",
            },
        )

        # 2. Login
        res = client.post(
            "/api/v1/auth/login",
            json={"username": "alice", "password": "AlicePassword!123"},
        )
        assert res.status_code == 200
        assert "access_token" in res.json()
        assert "session_token" in res.cookies

    def test_brute_force_lockout_enforcement(self, client):
        """Oral Defense Step 4: 5 consecutive failed logins trigger 15-min lockout."""
        client.post(
            "/api/v1/auth/register",
            json={
                "username": "victim_user",
                "email": "victim@enterprise.local",
                "password": "VictimValidPassword!123",
            },
        )

        # 4 failed attempts: return 401
        for i in range(4):
            res = client.post(
                "/api/v1/auth/login",
                json={"username": "victim_user", "password": "WrongPassword999!"},
            )
            assert res.status_code == 401

        # 5th failed attempt: returns 403 Forbidden with lockout notification
        res5 = client.post(
            "/api/v1/auth/login",
            json={"username": "victim_user", "password": "WrongPassword999!"},
        )
        assert res5.status_code == 403
        assert "Account locked" in res5.json()["detail"]

        # 6th attempt with CORRECT password is still rejected due to active lockout
        res_correct = client.post(
            "/api/v1/auth/login",
            json={"username": "victim_user", "password": "VictimValidPassword!123"},
        )
        assert res_correct.status_code == 403
        assert "temporarily locked" in res_correct.json()["detail"]


class TestAPISecretsAndRBAC:
    """Two-tier envelope encryption, Anti-IDOR, and Zero-Knowledge tests."""

    def _login(self, client, username, password):
        res = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": password},
        )
        token = res.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def test_secret_envelope_encryption_roundtrip(self, client):
        """Secret is stored via envelope encryption and decrypted back to plaintext."""
        # 1. Register and login
        client.post(
            "/api/v1/auth/register",
            json={"username": "alice", "email": "alice@local.test", "password": "AlicePassword!123"},
        )
        headers = self._login(client, "alice", "AlicePassword!123")

        # 2. Store secret
        secret_content = "SuperConfidentialServerKey_XYZ987654321"
        res_create = client.post(
            "/api/v1/secrets",
            json={"secret_name": "ProdDatabaseSecret", "plaintext": secret_content},
            headers=headers,
        )
        assert res_create.status_code == 201
        secret_id = res_create.json()["id"]

        # 3. List secrets (metadata only)
        res_list = client.post("/api/v1/secrets", headers=headers)
        res_list = client.get("/api/v1/secrets", headers=headers)
        assert res_list.status_code == 200
        assert len(res_list.json()) == 1
        assert "plaintext" not in res_list.json()[0]

        # 4. Decrypt secret
        res_detail = client.get(f"/api/v1/secrets/{secret_id}", headers=headers)
        assert res_detail.status_code == 200
        assert res_detail.json()["plaintext"] == secret_content

    def test_idor_protection_blocks_other_users(self, client):
        """Oral Defense Step 2: User B cannot access User A's secret (Anti-IDOR)."""
        # User A creates a secret
        client.post(
            "/api/v1/auth/register",
            json={"username": "alice", "email": "alice@test.local", "password": "AlicePassword!123"},
        )
        headers_alice = self._login(client, "alice", "AlicePassword!123")
        res_create = client.post(
            "/api/v1/secrets",
            json={"secret_name": "AliceSecret", "plaintext": "AliceClassifiedData"},
            headers=headers_alice,
        )
        alice_secret_id = res_create.json()["id"]

        # User B registers and attempts to retrieve Alice's secret
        client.post(
            "/api/v1/auth/register",
            json={"username": "bob_attacker", "email": "bob@test.local", "password": "BobPassword!123"},
        )
        headers_bob = self._login(client, "bob_attacker", "BobPassword!123")

        res_idor = client.get(f"/api/v1/secrets/{alice_secret_id}", headers=headers_bob)
        assert res_idor.status_code == 403
        assert "Access forbidden" in res_idor.json()["detail"]

    def test_zero_knowledge_admin_denied_secret_access(self, client):
        """Zero-Knowledge Model: Administrators CANNOT read user secrets."""
        # User creates secret
        client.post(
            "/api/v1/auth/register",
            json={"username": "alice", "email": "alice@test.local", "password": "AlicePassword!123"},
        )
        headers_alice = self._login(client, "alice", "AlicePassword!123")
        res_create = client.post(
            "/api/v1/secrets",
            json={"secret_name": "AliceSecret", "plaintext": "ConfidentialPayload"},
            headers=headers_alice,
        )
        secret_id = res_create.json()["id"]

        # Admin logs in
        headers_admin = self._login(client, "superadmin", "AdminSecurePassword123!")

        # Admin attempts to read secret
        res_admin = client.get(f"/api/v1/secrets/{secret_id}", headers=headers_admin)
        assert res_admin.status_code == 403
        assert "Zero-Knowledge policy" in res_admin.json()["detail"]

    def test_live_defense_bit_tampering_triggers_gcm_tag_failure(self, client):
        """Oral Defense Step 3: Modifying ciphertext in SQLite fails AES-GCM verification."""
        # 1. User creates secret
        client.post(
            "/api/v1/auth/register",
            json={"username": "alice", "email": "alice@test.local", "password": "AlicePassword!123"},
        )
        headers = self._login(client, "alice", "AlicePassword!123")
        res_create = client.post(
            "/api/v1/secrets",
            json={"secret_name": "TamperTarget", "plaintext": "AuthenticOriginalData"},
            headers=headers,
        )
        secret_id = res_create.json()["id"]

        # 2. Simulate attacker tampering directly with the SQLite database
        db = TestingSessionLocal()
        db_secret = db.execute(select(VaultSecret).where(VaultSecret.id == secret_id)).scalar_one()
        # Flip a character in the stored base64 ciphertext
        tampered = list(db_secret.encrypted_payload)
        tampered[0] = "B" if tampered[0] != "B" else "C"
        db_secret.encrypted_payload = "".join(tampered)
        db.commit()
        db.close()

        # 3. User attempts to retrieve secret
        res_tampered = client.get(f"/api/v1/secrets/{secret_id}", headers=headers)
        assert res_tampered.status_code == 400
        assert "Cryptographic integrity verification failed" in res_tampered.json()["detail"]


class TestAPIAuditAndKeys:
    """KMS key management and audit verification tests."""

    def _login(self, client, username, password):
        res = client.post(
            "/api/v1/auth/login",
            json={"username": username, "password": password},
        )
        return {"Authorization": f"Bearer {res.json()['access_token']}"}

    def test_admin_can_manage_and_rotate_keys(self, client):
        """Admins can generate and rotate Master Keys."""
        headers_admin = self._login(client, "superadmin", "AdminSecurePassword123!")

        # Generate new key
        res_create = client.post(
            "/api/v1/keys",
            json={"key_id": "k-finance-v1", "key_name": "Finance Department KEK"},
            headers=headers_admin,
        )
        assert res_create.status_code == 201
        assert res_create.json()["key_version"] == 1

        # Rotate key
        res_rotate = client.post("/api/v1/keys/k-finance-v1/rotate", headers=headers_admin)
        assert res_rotate.status_code == 200
        assert res_rotate.json()["key_version"] == 2

    def test_auditor_can_verify_audit_integrity(self, client):
        """Auditor can verify cryptographic SHA-256 and HMAC audit chain."""
        headers_auditor = self._login(client, "security_auditor", "AuditorSecurePassword123!")

        # Query audit verify
        res_verify = client.post("/api/v1/audit/verify", headers=headers_auditor)
        assert res_verify.status_code == 200
        assert res_verify.json()["valid"] is True
        assert res_verify.json()["total_records"] >= 1
