# PROJECT STATE & LAPTOP ONBOARDING BRIEFING
**Project**: Authenticated Enterprise Key Management Service (KMS) & Secret Vault  
**Academic Context**: ING5 SSIRE (Class of 2026) • *Art of Protecting Secrets* (Track 02: Protect)  
**Authors**: Ahmed Amine Ghenimi & Abdallah Dridi  
**GitHub Repository**: https://github.com/TiiPain/enterprise-kms-vault  
**Primary Specification**: `Project Specifications - Enterprise KMS & Vault`  

---

## 1. Executive Context & Architectural Decisions Made

1. **Framework & Stack**:
   * **Backend**: Python 3.11+ / 3.13, **FastAPI** + **Uvicorn** (chosen for async performance, Swagger UI at `/docs`, and defense demo speed).
   * **Database**: **SQLite** via **SQLAlchemy** (chosen over MongoDB because of strict ACID transactional integrity for cryptographic hash-chaining, foreign key cascade protection against orphaned secrets, zero background daemon crashes, and seamless live bit-tamper inspection on disk).
   * **Cryptography**: `cryptography` library (`AESGCM` 256-bit).
   * **Identity**: `argon2-cffi` (Argon2id memory-hard password hashing).
   * **Testing**: `pytest`, compatible with Burp Suite interception.

2. **Core Security Architecture (Reviewed & Approved)**:
   * **Two-Tier Envelope Encryption**:
     - Plaintext secret is encrypted with a transient 256-bit DEK using **AES-256-GCM** (unique 96-bit random nonce + 128-bit authentication tag).
     - The transient DEK is wrapped under the Master Key (KEK) using AES-256-GCM.
     - Plaintext DEK is scrubbed immediately from memory.
     - Database stores only high-entropy ciphertext, wrapped DEK, nonces, and tags. Zero plaintext at rest.
   * **Zero-Knowledge RBAC & Anti-IDOR**:
     - Database queries strictly enforce `WHERE id = :secret_id AND owner_id = :session_user_id`.
     - Administrators have zero access to read or decrypt user secrets (Zero-Knowledge model).
   * **Defensive Controls**:
     - Argon2id password hashing (`m=64MB, t=2, p=2`).
     - Brute-force protection: in-memory / DB rate limiter locking accounts for **15 minutes** after **5 consecutive failed attempts**.
     - Secure session tokens transmitted via `HttpOnly`, `SameSite=Strict`, `Secure` cookies.
   * **Tamper-Evident Audit Trail**:
     - Cryptographic SHA-256 hash chaining: `previous_record_hash = SHA-256(prev_hash || timestamp || actor_id || action || resource_id)`.
     - HMAC-SHA256 signature verification using server-side `AUDIT_HMAC_SECRET`.

3. **User Guidelines & Workflow Preferences**:
   * **Strict Git Cleanliness**: Only clean project source files, configuration templates (`.env.example`), and `.gitignore` in GitHub. **Never commit PDFs, notes, or real `.env` secret files**.
   * **Permission Rule**: **Never proceed with major phases without asking permission first**.
   * **Live Defense Orientation**: Code and UI are built to support the 5-minute live oral defense (Step 1: DB inspection, Step 2: Burp Suite IDOR interception, Step 3: Bit-flipping AES-GCM tag verification failure, Step 4: Brute-force lockout and audit verification).

---

## 2. Current Implementation State

* **Completed**:
  1. Git & GitHub CLI configured under user profile `TiiPain`.
  2. GitHub repository initialized and live: `https://github.com/TiiPain/enterprise-kms-vault`.
  3. Clean project files committed: `.gitignore`, `requirements.txt`, `.env.example`, and modern open-source `README.md`.
  4. Database schema (4 tables: `users`, `master_keys`, `vault_secrets`, `audit_logs`) and crypto design reviewed and approved.

* **Next Immediate Step (Phase 1)**:
  * Implement `app/crypto/envelope.py` (transient DEK generation, AES-256-GCM payload encryption/decryption, KEK wrapping/unwrapping).
  * Implement `tests/test_crypto.py` (proving encryption roundtrip, bit-flipping tag failure `InvalidTag`, and key wrapping).
  * Run `pytest` to verify 100% cryptographic pass.

---

## 3. Laptop Resume Prompt (Copy & Paste this into Antigravity on your Laptop)

```text
I am continuing my project "Authenticated Enterprise Key Management Service (KMS) & Secret Vault" from my desktop. 
Please read PROJECT_STATE_FOR_LAPTOP.md in the repository root.
All previous context, architectural decisions (FastAPI, SQLite, AES-256-GCM envelope encryption, Argon2id, zero-knowledge RBAC, and tamper-evident audit logging), and Git setup are documented there.
We are ready to start Phase 1 (Core Cryptographic Engine & Unit Tests). Please ask for my permission before writing code as per my workflow preference.
```
