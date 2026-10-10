"""Live Oral Defense - Step 2: IDOR / BOLA Attack Simulation (Burp Suite Simulation).

Demonstrates that an attacker intercepting requests and altering secret IDs cannot
read or decrypt secrets belonging to another user.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from app.main import app, seed_default_master_key
from app.models.database import engine, init_db

def run_step2_demo():
    print("=" * 70)
    print("  ORAL DEFENSE STEP 2: IDOR ATTACK SIMULATION (BURP SUITE REPEATER)")
    print("=" * 70)

    init_db(engine)
    seed_default_master_key()
    client = TestClient(app)

    # 1. Victim (Alice) creates a confidential secret
    alice_user = "alice_finance"
    alice_pass = "AliceSecurePass!123"
    print(f"\n[*] 1. Victim '{alice_user}' creates a confidential secret...")
    client.post("/api/v1/auth/register", json={"username": alice_user, "email": "alice@corp.internal", "password": alice_pass})
    login_alice = client.post("/api/v1/auth/login", json={"username": alice_user, "password": alice_pass})
    headers_alice = {"Authorization": f"Bearer {login_alice.json()['access_token']}"}

    create_res = client.post(
        "/api/v1/secrets",
        json={"secret_name": "PayrollSalaryMatrix", "plaintext": "AliceExecutiveSalary:$250,000/yr"},
        headers=headers_alice,
    )
    secret_id = create_res.json()["id"]
    print(f"    Secret Created: ID = {secret_id}")

    # 2. Attacker (Bob) authenticates
    bob_user = "bob_attacker"
    bob_pass = "BobAttackerPass!456"
    print(f"\n[*] 2. Attacker '{bob_user}' authenticates with valid credentials...")
    client.post("/api/v1/auth/register", json={"username": bob_user, "email": "bob@corp.internal", "password": bob_pass})
    login_bob = client.post("/api/v1/auth/login", json={"username": bob_user, "password": bob_pass})
    headers_bob = {"Authorization": f"Bearer {login_bob.json()['access_token']}"}

    # 3. Attacker intercepts and replaces secret ID with Alice's secret ID
    print(f"\n[*] 3. Bob attempts IDOR attack: GET /api/v1/secrets/{secret_id}...")
    print(f"    Request Authorization Header: Bob's Bearer token")
    print(f"    Target Secret ID: Alice's Secret ({secret_id})")

    res = client.get(f"/api/v1/secrets/{secret_id}", headers=headers_bob)

    print(f"\n[*] 4. Server Response:")
    print(f"    HTTP Status Code: {res.status_code}")
    print(f"    Response Body:    {res.json()}")

    if res.status_code == 403:
        print("\n[+] DEFENSE VERIFICATION RESULT:")
        print("    [BLOCKED] Anti-IDOR server-side ownership guard successfully prevented unauthorized read.")
        print("    [BLOCKED] Server returned 403 Forbidden. Cryptographic decryption aborted.")
    else:
        print(f"\n[-] FAILED: Expected HTTP 403, got {res.status_code}")

    print("=" * 70)

if __name__ == "__main__":
    run_step2_demo()
