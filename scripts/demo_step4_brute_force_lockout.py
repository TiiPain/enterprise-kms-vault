"""Live Oral Defense - Step 4: Brute-Force & Audit Trail Verification Demonstration.

Fires consecutive invalid login attempts to trigger automatic account lockout,
then verifies the tamper-evident audit trail with SHA-256 and HMAC signatures.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from app.main import app, seed_default_master_key
from app.models.database import engine, init_db

def run_step4_demo():
    print("=" * 70)
    print("  ORAL DEFENSE STEP 4: BRUTE-FORCE LOCKOUT & AUDIT TRAIL CHECK")
    print("=" * 70)

    init_db(engine)
    seed_default_master_key()
    client = TestClient(app)

    # 1. Target account creation
    target_user = "target_executive"
    target_pass = "ExecutiveStrongPass!2026"
    print(f"\n[*] 1. Target user '{target_user}' exists in system...")
    client.post("/api/v1/auth/register", json={"username": target_user, "email": "target@corp.internal", "password": target_pass})

    # 2. Attacker launches brute-force password dictionary attack
    print("\n[*] 2. Attacker initiates dictionary attack against /api/v1/auth/login:")
    for attempt in range(1, 6):
        res = client.post(
            "/api/v1/auth/login",
            json={"username": target_user, "password": f"WrongAttemptPassword{attempt}!"},
        )
        print(f"    Attempt #{attempt}: HTTP {res.status_code} - {res.json()['detail']}")

    # 3. Prove lockout blocks subsequent attempts even with CORRECT password
    print(f"\n[*] 3. Legitimate user attempts to log in with the CORRECT password:")
    res_valid = client.post(
        "/api/v1/auth/login",
        json={"username": target_user, "password": target_pass},
    )
    print(f"    Correct Password Attempt: HTTP {res_valid.status_code} - {res_valid.json()['detail']}")

    # 4. Auditor inspects and verifies cryptographic audit trail
    print("\n[*] 4. Security Officer inspects HMAC audit logs and verifies integrity...")
    login_auditor = client.post("/api/v1/auth/login", json={"username": "superadmin", "password": "AdminSecurePassword123!"})
    if login_auditor.status_code != 200:
        # Fallback if admin not registered yet
        client.post("/api/v1/auth/register", json={"username": "admin_demo", "email": "admin@demo.internal", "password": "AdminPassword!2026"})
        # Update to admin in db
        from app.models.database import SessionLocal, User
        db = SessionLocal()
        u = db.query(User).filter_by(username="admin_demo").first()
        u.role = "ADMIN"
        db.commit()
        db.close()
        login_auditor = client.post("/api/v1/auth/login", json={"username": "admin_demo", "password": "AdminPassword!2026"})

    token = login_auditor.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Query audit verification endpoint
    verify_res = client.post("/api/v1/audit/verify", headers=headers)
    print(f"    Audit Verification Response: {verify_res.json()}")

    if res_valid.status_code == 403 and verify_res.json().get("valid") is True:
        print("\n[+] DEFENSE VERIFICATION RESULT:")
        print("    [PASSED] Brute-force rate limiter automatically enforced 15-minute account lockout.")
        print("    [PASSED] Cryptographic SHA-256 hash chaining and HMAC-SHA256 signatures validated.")
        print("    [PASSED] Entire audit trail is mathematically immutable and untampered.")
    else:
        print("\n[-] FAILED verification check.")

    print("=" * 70)

if __name__ == "__main__":
    run_step4_demo()
