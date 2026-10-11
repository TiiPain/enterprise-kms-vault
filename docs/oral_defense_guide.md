# 5-Minute Live Oral Defense Rehearsal & Jury Runbook

**Project**: Authenticated Enterprise Key Management Service (KMS) & Secret Vault  
**Academic Program**: ING5 SSIRE (Class of 2026) — *Art of Protecting Secrets* (Track 02: Protect)  
**Authors / Presenters**: Ahmed Amine Ghenimi & Abdallah Dridi  
**Repository**: [https://github.com/TiiPain/enterprise-kms-vault](https://github.com/TiiPain/enterprise-kms-vault)  
**Target Duration**: 5 Minutes Presentation + 5 Minutes Jury Q&A  

---

## 1. Presentation Strategy & Role Allocation

* **Speaker A (Ahmed Amine Ghenimi)**: Architecture overview, Two-Tier Envelope Encryption mechanics, Anti-IDOR defense demonstration, and final conclusion.
* **Speaker B (Abdallah Dridi)**: Live storage-at-rest inspection, bit-tampering demonstration, brute-force lockout defenses, and cryptographic audit chain verification.

### Pre-Defense Setup (T minus 5 minutes)
1. Open terminal 1 and start the backend:
   ```bash
   uvicorn app.main:app --port 8000 --reload
   ```
2. Open Chrome/Firefox to the Web UI Dashboard: `http://127.0.0.1:8000`.
3. Open a second terminal window in the project root for running live demo scripts or inspecting SQLite.

---

## 2. Timed 5-Minute Presentation Script

### Minute 0:00 – 1:00 | Introduction & Two-Tier Architecture (Ahmed)
> **Ahmed speaks:**  
> "Good morning, members of the jury. Today, Abdallah and I are presenting our project for Track 02: Protect — an **Authenticated Enterprise Key Management Service (KMS) & Secret Vault**.  
> In modern cybersecurity, traditional vaults suffer from a major design flaw: they rely on static database encryption where a single database leak or rogue DBA exposes all secrets.  
> To solve this, we patterned our architecture after AWS KMS and HashiCorp Vault, implementing **Two-Tier Envelope Encryption**:
> * We generate an ephemeral, transient 256-bit Data Encryption Key (DEK) in memory per secret write.
> * We encrypt the secret with this DEK using **AES-256-GCM** with a unique 96-bit nonce and 128-bit authentication tag.
> * We wrap the DEK under a rotatable Master Key (KEK), which itself is encrypted under a Root KEK.
> * The plaintext DEK is immediately purged from RAM.  
> In our database, zero plaintext ever touches persistent storage. Let us prove this live."

---

### Minute 1:00 – 2:00 | Defense Step 1: Storage at Rest Inspection (Abdallah)
> **Abdallah speaks (Live Action on Screen):**  
> *(Navigates to the "Live Defense Lab" tab on the Web UI or runs `python scripts/demo_step1_inspect_db.py`)*  
> "Here on screen, we have stored a secret named `ProductionDatabasePassword` with plaintext `SuperSecretPassword2026!`.  
> If we query the underlying SQLite database directly on disk:
> * The `encrypted_payload` field contains high-entropy ciphertext produced by AES-256-GCM.
> * The `encrypted_dek` field stores the transient key wrapped under Master Key `k-default-root-v1`.
> * The `payload_nonce` and `payload_tag` store the initialization vector and authentication tag.
> Even if an attacker steals the entire database file or memory snapshot, they obtain zero plaintext."

---

### Minute 2:00 – 3:00 | Defense Step 2: Broken Object-Level Authorization (IDOR) Block (Ahmed)
> **Ahmed speaks (Live Action on Screen):**  
> *(Runs `python scripts/demo_step2_idor_attack.py` or demonstrates with Burp Suite)*  
> "Next, we address the #1 API vulnerability in the OWASP Top 10: Insecure Direct Object References (IDOR/BOLA).  
> In our system, User A (Alice) owns secret `sec-alice-1234`.  
> Now, User B (Bob) authenticates with valid credentials, intercepts the API request, and attempts to read Alice's secret by calling `GET /api/v1/secrets/sec-alice-1234`.  
> As you can see, our server immediately rejects Bob with **HTTP 403 Forbidden**.  
> Our RBAC guard at `app/core/rbac.py` enforces server-side ownership: `user_id == secret.owner_id`. Furthermore, the attempted violation is automatically logged as an `IDOR_ATTEMPT_BLOCKED` event in our immutable audit chain."

---

### Minute 3:00 – 4:00 | Defense Step 3: Direct Ciphertext Bit-Tampering Attack (Abdallah)
> **Abdallah speaks (Live Action on Screen):**  
> *(Clicks 'Execute Bit-Tamper & Decrypt Test' on the UI or runs `python scripts/demo_step3_bit_tamper_attack.py`)*  
> "Now, let's execute an attack on the cryptographic layer itself.  
> Suppose an attacker gains write access to SQLite and flips just **1 single bit** inside the stored ciphertext in an attempt to alter decrypted data.  
> When the owner calls the decryption endpoint:
> * The server unwraps the DEK, but AES-256-GCM evaluates the 128-bit GHASH authentication tag over the modified ciphertext.
> * The verification fails mathematically.
> * The cryptography engine raises `cryptography.exceptions.InvalidTag`.
> * The server intercepts the exception, rejects the request with **HTTP 400 Bad Request**, and logs `TAMPER_DETECT_INTEGRITY_FAIL`.  
> Cryptographic integrity is fully guaranteed: tampered data is never released."

---

### Minute 4:00 – 5:00 | Defense Steps 4 & 5: Brute-Force Lockout & Cryptographic Audit Chain (Ahmed & Abdallah)
> **Ahmed speaks:**  
> "At the authentication layer, passwords are protected by **Argon2id** configured with 64 megabytes of memory and 2 iterations to resist GPU-based cracking.  
> If an attacker attempts a brute-force attack, upon the **5th consecutive failed attempt**, the account is locked for **15 minutes**. Further requests are rejected immediately before computing expensive hashes, preventing CPU denial-of-service."
>
> **Abdallah speaks (Clicks 'Verify Chain Integrity' on Tab 4):**  
> "Finally, our audit trail is cryptographically tamper-evident. Every action is chained using:  
> $$H_i = \text{SHA-256}(H_{i-1} \parallel \text{timestamp} \parallel \text{actor} \parallel \text{action} \parallel \text{resource})$$  
> and signed with an HMAC-SHA256 signature.  
> As you can see, our continuous verification algorithm mathematically confirms all records are 100% intact. If any row is altered or deleted, the verifier flags the exact corrupted record index immediately.  
> Our system achieves 100% test pass rate across all 75 automated security unit and integration tests. We welcome your questions."

---

## 3. Top 10 Anticipated Jury Questions & Killer Answers

### Q1: Why did you choose AES-256-GCM instead of AES-256-CBC with HMAC-SHA256?
* **Answer**: "AES-GCM is an Authenticated Encryption with Associated Data (AEAD) scheme that provides confidentiality and integrity in a single cryptographic primitive. Unlike AES-CBC, which requires manual 'Encrypt-then-MAC' construction and is notoriously vulnerable to padding oracle attacks (such as POODLE and Lucky Thirteen), GCM computes a 128-bit GHASH tag over ciphertext and nonces without padding, providing mathematical protection against chosen-ciphertext attacks."

### Q2: Where is the Root KEK stored in a production enterprise environment?
* **Answer**: "In our local deployment, the Root KEK is supplied via a secure environment variable (`ROOT_MASTER_KEY_HEX`). In an enterprise production environment, the Root KEK is anchored in a Hardware Security Module (HSM) compliant with FIPS 140-2 Level 3, or managed via cloud KMS (AWS KMS, GCP Cloud KMS, or HashiCorp Vault Transit engine). The application server never holds the root key material on disk."

### Q3: Why Argon2id instead of bcrypt or PBKDF2?
* **Answer**: "Argon2id won the Password Hashing Competition (PHC) because it is a hybrid algorithm that defends against both side-channel cache-timing attacks (via Argon2d) and GPU/ASIC massively parallel dictionary attacks (via Argon2i). By requiring 64MB of dedicated RAM per hash evaluation, an attacker cannot efficiently parallelize cracking on GPUs, whereas bcrypt and PBKDF2 use negligible memory and can be cracked rapidly on modern graphics cards."

### Q4: Can an Administrator decrypt a standard user's secret if they have full access?
* **Answer**: "No. We enforced a strict **Zero-Knowledge Administration** architecture. The `ADMIN` role is programmatically barred from secret retrieval endpoints. Even if an administrator intercepts an encrypted payload, they cannot decrypt it through the application without authenticating as that user. In our audit log, any access attempt by an administrator to user secrets is blocked and flagged as a security violation."

### Q5: What happens if an attacker modifies an old audit log row and cascades the recalculation of all downstream SHA-256 hashes?
* **Answer**: "The attack will still fail. While the attacker can recompute the SHA-256 chained hashes, they do not possess the server-side `AUDIT_HMAC_SECRET`. Every record is signed with an HMAC-SHA256 signature over its hash. When our verifier runs, the HMAC signature verification on the modified record fails immediately, detecting the forgery."

### Q6: How do you prevent nonce (IV) reuse in AES-GCM?
* **Answer**: "Reusing a 96-bit nonce with the same key in AES-GCM destroys the authenticity guarantee and can allow an attacker to forge GHASH authentication tags. In our implementation, every single encryption call generates a fresh 96-bit random vector using `os.urandom()`, which taps directly into the operating system's cryptographic pseudo-random number generator (CSPRNG). With a 96-bit random nonce and transient DEKs that are unique per secret, the probability of a collision is mathematically negligible ($< 2^{-32}$ after millions of operations)."

### Q7: Why use Envelope Encryption instead of just encrypting everything with the Master Key?
* **Answer**: "Envelope encryption provides three major operational benefits:
  1. **Performance**: Encrypting large payloads locally with transient DEKs avoids sending bulky data over the network to a central KMS or HSM.
  2. **Blast Radius & Key Limits**: AES-GCM has limits on how many records should be encrypted under a single key before nonce collision risks increase. Using a fresh DEK per secret guarantees no key is overused.
  3. **Key Rotation Simplicity**: Rotating a Master Key (KEK) only requires re-wrapping the compact 256-bit DEKs, rather than decrypting and re-encrypting gigabytes of user payloads."

### Q8: How does your system handle key rotation for existing secrets?
* **Answer**: "Our KMS models key state as `ACTIVE`, `ROTATED`, or `REVOKED`. When a Master Key is rotated, a new key version becomes `ACTIVE` for all new writes. Existing secrets retain their foreign-key reference to the key version used when they were created. They remain fully decryptable as long as that key version is in `ROTATED` status. A background migration job can re-wrap their DEKs under the new KEK without touching the plaintext payloads."

### Q9: What happens if the SQLite database file is stolen or leaked?
* **Answer**: "The stolen database reveals zero secret plaintexts. The payloads are AES-256-GCM ciphertexts, and the DEKs are wrapped under the Master KEK. To decrypt anything, an adversary would also need the Master KEK (which is itself encrypted) and the Root KEK stored strictly in the server environment. Without the Root KEK, the database is mathematically undecryptable."

### Q10: How does your Web UI prevent Clickjacking and Cross-Site Scripting (XSS)?
* **Answer**: "All HTTP responses pass through our enterprise security middleware which sets:
  * `X-Frame-Options: DENY` (disables iframe embedding entirely).
  * `X-Content-Type-Options: nosniff` (prevents MIME confusion).
  * Strict `Content-Security-Policy` restricting script sources to authorized origins and blocking inline eval.
  * In the frontend DOM, all decrypted plaintexts and user inputs are escaped via `escapeHtml()` before insertion into innerHTML, preventing DOM-based XSS."

---

## 4. Live Command Execution Cheat-Sheet

| Step | Script / Command | Expected Visual Output |
| :--- | :--- | :--- |
| **Step 1: DB Inspection** | `python scripts/demo_step1_inspect_db.py` | Prints SQLite row: Base64 ciphertext, Base64 wrapped DEK, 0 plaintext. |
| **Step 2: Anti-IDOR** | `python scripts/demo_step2_idor_attack.py` | Bob requests Alice's secret $\rightarrow$ `HTTP 403 Forbidden` (`can_access_secret` block). |
| **Step 3: Bit-Tamper** | `python scripts/demo_step3_bit_tamper_attack.py` | Flips byte 0 $\rightarrow$ `HTTP 400 Bad Request` (`InvalidTag` rejection). |
| **Step 4: Lockout** | `python scripts/demo_step4_brute_force_lockout.py` | 5 failed logins $\rightarrow$ Account locked for 15 minutes (`HTTP 403`). |
| **Step 5: Audit Tamper**| `python scripts/demo_step5_tamper_audit_log.py` | Alters log row $\rightarrow$ Verifier flags `corrupted_record_id` and HMAC mismatch. |
| **Unit Tests** | `python -m pytest -v` | **75 passed in 6.45s (100% pass rate)**. |
