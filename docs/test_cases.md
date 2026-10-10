# Security Test Cases & Burp Suite Exploitation Guide

This document provides step-by-step instructions and raw HTTP request payloads to reproduce all security tests using **Burp Suite (Community / Professional)** or **cURL**.

---

## 1. Test Setup & Burp Suite Proxy Configuration

1. **Start the KMS Backend**:
   ```bash
   uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```
2. **Configure Burp Suite**:
   * Set Burp Suite Proxy listener to `127.0.0.1:8080`.
   * Configure your browser or client proxy to route through `127.0.0.1:8080`.
   * Access Swagger documentation at `http://127.0.0.1:8000/docs`.

---

## 2. Test Case 1: Zero Plaintext at Rest & Database Inspection

* **Objective**: Prove that user secrets and Data Encryption Keys (DEKs) are never stored in plaintext on disk.
* **Test Step**:
  1. Register a user and store a confidential secret via `POST /api/v1/secrets`.
  2. Inspect the SQLite database on disk using the sqlite3 CLI or SQLite Viewer:
     ```bash
     sqlite3 keyvault.db "SELECT id, secret_name, encrypted_payload, encrypted_dek, payload_nonce, payload_tag FROM vault_secrets;"
     ```
* **Expected Result**:
  * `encrypted_payload`: High-entropy Base64 ciphertext produced by AES-256-GCM.
  * `encrypted_dek`: Base64 transient key wrapped under the Master KEK.
  * `payload_nonce`: 12-byte initialization vector in Base64.
  * `payload_tag`: 16-byte authentication tag in Base64.
  * **Zero plaintext** exists in table rows or SQLite journal files.

---

## 3. Test Case 2: Broken Object-Level Authorization (IDOR / BOLA)

* **Objective**: Verify that User B cannot read or delete User A's secret by manipulating the `secret_id` URL parameter in Burp Suite.
* **Attack Procedure**:
  1. In Burp Suite, authenticate as **User A (Alice)** and create a secret:
     ```http
     POST /api/v1/secrets HTTP/1.1
     Host: 127.0.0.1:8000
     Authorization: Bearer <ALICE_TOKEN>
     Content-Type: application/json

     {
       "secret_name": "ExecutiveSalary",
       "plaintext": "ConfidentialSalary$200k"
     }
     ```
     Note the returned secret ID (e.g., `sec-alice-1234`).
  2. In Burp Suite Repeater, craft a retrieval request authenticated as **User B (Bob)**:
     ```http
     GET /api/v1/secrets/sec-alice-1234 HTTP/1.1
     Host: 127.0.0.1:8000
     Authorization: Bearer <BOB_TOKEN>
     ```
* **Expected Server Response**:
  ```http
  HTTP/1.1 403 Forbidden
  Content-Type: application/json

  {
    "detail": "Access forbidden: you do not have permission to view this secret"
  }
  ```
* **Security Control**: `can_access_secret(user_id, owner_id, role)` strictly validates object ownership. The incident is immediately recorded in the cryptographic audit trail as `IDOR_ATTEMPT_BLOCKED`.

---

## 4. Test Case 3: AES-256-GCM Ciphertext Bit-Flipping Attack

* **Objective**: Prove that altering even a single bit of stored ciphertext triggers an authentication tag mismatch (`InvalidTag`), preventing ciphertext manipulation.
* **Attack Procedure**:
  1. Locate the target secret in SQLite:
     ```bash
     sqlite3 keyvault.db "SELECT encrypted_payload FROM vault_secrets WHERE secret_name = 'ExecutiveSalary';"
     ```
  2. Modify a single character in the stored Base64 ciphertext:
     ```bash
     sqlite3 keyvault.db "UPDATE vault_secrets SET encrypted_payload = 'A' || SUBSTR(encrypted_payload, 2) WHERE secret_name = 'ExecutiveSalary';"
     ```
  3. Send a retrieval request through Burp Suite:
     ```http
     GET /api/v1/secrets/sec-alice-1234 HTTP/1.1
     Host: 127.0.0.1:8000
     Authorization: Bearer <ALICE_TOKEN>
     ```
* **Expected Server Response**:
  ```http
  HTTP/1.1 400 Bad Request
  Content-Type: application/json

  {
    "detail": "Cryptographic integrity verification failed: ciphertext or tag was altered"
  }
  ```
* **Security Control**: The underlying `cryptography` library catches `InvalidTag`. Decryption immediately halts and no corrupted plaintext is returned.

---

## 5. Test Case 4: Brute-Force Authentication & Automatic Account Lockout

* **Objective**: Verify that Burp Suite Intruder dictionary attacks are blocked after 5 consecutive failed attempts.
* **Attack Procedure**:
  1. In Burp Suite Intruder, target `/api/v1/auth/login`:
     ```http
     POST /api/v1/auth/login HTTP/1.1
     Host: 127.0.0.1:8000
     Content-Type: application/json

     {
       "username": "victim_user",
       "password": "§password_payload§"
     }
     ```
  2. Send 5 invalid login requests with random passwords.
* **Expected Results**:
  * **Attempts 1 to 4**: `HTTP 401 Unauthorized` with remaining attempts counter.
  * **Attempt 5**: `HTTP 403 Forbidden` (`Account locked! Exceeded 5 failed attempts. Locked for 15 minutes.`).
  * **Attempt 6 (with valid password)**: `HTTP 403 Forbidden` (`Account is temporarily locked`).
* **Security Control**: The account lockout mechanism persists across requests, and an `ACCOUNT_LOCKOUT` audit record is signed into the cryptographic log.

---

## 6. Test Case 5: Audit Log Tamper-Evidence & Integrity Verification

* **Objective**: Prove that unauthorized modification of the audit trail breaks the sequential SHA-256 hash chain and invalidates HMAC signatures.
* **Attack Procedure**:
  1. Query baseline audit verification as an Auditor or Admin:
     ```http
     POST /api/v1/audit/verify HTTP/1.1
     Host: 127.0.0.1:8000
     Authorization: Bearer <ADMIN_OR_AUDITOR_TOKEN>
     ```
     Response: `{"valid": true, "total_records": N, "corrupted_record_id": null}`
  2. Tamper with an audit row directly in SQLite:
     ```bash
     sqlite3 keyvault.db "UPDATE audit_logs SET action = 'ALTERED_ACTION' WHERE id = 1;"
     ```
  3. Re-run verification request in Burp Suite:
     ```http
     POST /api/v1/audit/verify HTTP/1.1
     Host: 127.0.0.1:8000
     Authorization: Bearer <ADMIN_OR_AUDITOR_TOKEN>
     ```
* **Expected Server Response**:
  ```http
  HTTP/1.1 200 OK
  Content-Type: application/json

  {
    "valid": false,
    "total_records": N,
    "corrupted_record_id": 1,
    "reason": "Hash chain violation at record 1: stored hash does not match computed chained hash."
  }
  ```
