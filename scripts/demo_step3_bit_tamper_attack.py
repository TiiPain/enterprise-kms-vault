"""Live Oral Defense - Step 3: Ciphertext Bit-Tampering Demonstration.

Modifies a single character of ciphertext directly inside the SQLite database to prove
that AES-256-GCM authentication tag verification strictly detects data alteration and aborts.
"""

import sqlite3
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient
from app.main import app, seed_default_master_key
from app.models.database import engine, init_db

def run_step3_demo():
    print("=" * 70)
    print("  ORAL DEFENSE STEP 3: CIPHERTEXT BIT-TAMPERING TEST (AES-256-GCM)")
    print("=" * 70)

    init_db(engine)
    seed_default_master_key()
    client = TestClient(app)

    # 1. User creates an authentic secret
    user = "alice_crypto"
    password = "AliceCryptoPass!123"
    print(f"\n[*] 1. Creating authentic secret for '{user}'...")
    client.post("/api/v1/auth/register", json={"username": user, "email": "alice_crypto@corp.internal", "password": password})
    login_res = client.post("/api/v1/auth/login", json={"username": user, "password": password})
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    original_text = "AUTHENTIC_TRANSACTION_PAYLOAD_TRANSFER_$50000"
    create_res = client.post(
        "/api/v1/secrets",
        json={"secret_name": "WireTransferInstructions", "plaintext": original_text},
        headers=headers,
    )
    secret_id = create_res.json()["id"]
    print(f"    Secret Created: ID = {secret_id}")

    # 2. Direct database tampering
    db_path = Path("keyvault.db")
    if not db_path.exists():
        print("    [!] keyvault.db not found on disk. Ensure server is using SQLite disk DB.")
        return

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT encrypted_payload FROM vault_secrets WHERE id = ?", (secret_id,))
    original_ciphertext = cursor.fetchone()[0]

    # Tamper with first character
    tampered_list = list(original_ciphertext)
    tampered_list[0] = "Z" if tampered_list[0] != "Z" else "A"
    tampered_ciphertext = "".join(tampered_list)

    print(f"\n[*] 2. Attacker modifies 1 byte directly inside SQLite database:")
    print(f"    Original Ciphertext: {original_ciphertext[:30]}...")
    print(f"    Tampered Ciphertext: {tampered_ciphertext[:30]}...")

    cursor.execute("UPDATE vault_secrets SET encrypted_payload = ? WHERE id = ?", (tampered_ciphertext, secret_id))
    conn.commit()
    conn.close()

    # 3. Request secret decryption via API
    print(f"\n[*] 3. Legitimate user requests decryption of the tampered secret...")
    res = client.get(f"/api/v1/secrets/{secret_id}", headers=headers)

    print(f"\n[*] 4. Server Response:")
    print(f"    HTTP Status Code: {res.status_code}")
    print(f"    Response Body:    {res.json()}")

    if res.status_code == 400 and ("altered" in str(res.json()) or "integrity" in str(res.json())):
        print("\n[+] CRYPTOGRAPHIC DEFENSE RESULT:")
        print("    [BLOCKED] AES-256-GCM Galois authentication tag check failed.")
        print("    [BLOCKED] Cryptographic engine threw InvalidTag exception.")
        print("    [BLOCKED] Decryption was immediately rejected; zero corrupted data was returned.")
    else:
        print(f"\n[-] FAILED: Expected 400 InvalidTag rejection, got {res.status_code}")

    print("=" * 70)

if __name__ == "__main__":
    run_step3_demo()
