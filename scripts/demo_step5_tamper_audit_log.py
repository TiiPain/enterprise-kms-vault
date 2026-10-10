"""Live Oral Defense - Audit Trail Tamper-Evidence Demonstration.

Directly alters an audit log record inside SQLite to demonstrate that
the SHA-256 hash chain and HMAC-SHA256 signature verification immediately flags the tampering.
"""

import sqlite3
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from app.main import app, seed_default_master_key
from app.models.database import SessionLocal, User, init_db, engine
from app.core.security import hash_password

def run_step5_demo():
    print("=" * 70)
    print("  ORAL DEFENSE STEP 5: AUDIT LOG TAMPER-EVIDENCE DEMONSTRATION")
    print("=" * 70)

    init_db(engine)
    seed_default_master_key()
    client = TestClient(app)

    # 1. Ensure admin user exists
    db = SessionLocal()
    admin = db.query(User).filter_by(username="audit_verifier").first()
    if not admin:
        admin = User(
            username="audit_verifier",
            email="verifier@enterprise.local",
            password_hash=hash_password("VerifierPass!2026"),
            role="ADMIN",
        )
        db.add(admin)
        db.commit()
    db.close()

    # 2. Authenticate admin
    login_res = client.post("/api/v1/auth/login", json={"username": "audit_verifier", "password": "VerifierPass!2026"})
    headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    # 3. Check baseline audit chain before tampering
    print("\n[*] 1. Baseline verification before tampering:")
    pre_verify = client.post("/api/v1/audit/verify", headers=headers).json()
    print(f"    Baseline Status: valid = {pre_verify['valid']}, total_records = {pre_verify['total_records']}")

    # 4. Simulate insider threat tampering directly with SQLite audit_logs table
    db_path = Path("keyvault.db")
    if not db_path.exists():
        print("    [!] keyvault.db not found on disk.")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT id, actor_id, action FROM audit_logs ORDER BY id DESC LIMIT 1")
    last_row = cursor.fetchone()
    if not last_row:
        print("    [!] No audit records in database to tamper with.")
        conn.close()
        return

    target_id = last_row[0]
    original_action = last_row[2]
    tampered_action = "COVER_UP_ILLEGAL_EXFILTRATION"

    print(f"\n[*] 2. Rogue database admin modifies Record #{target_id}:")
    print(f"    Original Action: '{original_action}'")
    print(f"    Tampered Action: '{tampered_action}'")

    cursor.execute("UPDATE audit_logs SET action = ? WHERE id = ?", (tampered_action, target_id))
    conn.commit()
    conn.close()

    # 5. Run audit verification
    print(f"\n[*] 3. Running cryptographic verification endpoint /api/v1/audit/verify...")
    post_verify = client.post("/api/v1/audit/verify", headers=headers).json()

    print(f"\n[*] 4. Cryptographic Verification Engine Response:")
    print(f"    Valid:               {post_verify['valid']}")
    print(f"    Total Records:       {post_verify['total_records']}")
    print(f"    Corrupted Record ID: {post_verify['corrupted_record_id']}")
    print(f"    Reason:              {post_verify['reason']}")

    if post_verify["valid"] is False and post_verify["corrupted_record_id"] == target_id:
        print("\n[+] TAMPER-EVIDENT DEFENSE RESULT:")
        print("    [FLAGGED] Alteration detected by cryptographic SHA-256 hash chaining.")
        print("    [FLAGGED] HMAC-SHA256 signature verification failed.")
        print("    [FLAGGED] The audit trail is proven tamper-evident.")
    else:
        print("\n[-] Tamper detection check failed.")

    print("=" * 70)

if __name__ == "__main__":
    run_step5_demo()
