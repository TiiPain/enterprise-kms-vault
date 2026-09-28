# Authenticated Enterprise Key Management Service (KMS) & Secret Vault

**Academic Program**: ING5 SSIRE (Class of 2026) • Course: *Art of Protecting Secrets*  
**Track**: Project 2: Protect (Secure Authentication & Cryptography System)  
**Authors**: Ahmed Amine Ghenimi & Abdallah Dridi  

---

## 1. Executive Summary & Problem Statement

In modern enterprise architectures, sensitive credentials (database passwords, external API tokens, private keys) are frequently mismanaged—stored in plaintext configuration files, insecure environment variables, or flat unencrypted database tables. If an unauthorized actor gains read access to the database or backups, the entire enterprise perimeter is compromised.

This project delivers a **Secure Authentication & Cryptographic Storage System (KMS & Secret Vault)** patterned after enterprise architectures like AWS KMS and HashiCorp Vault. The system enforces:
1. **Two-Tier Envelope Encryption** (AES-256-GCM) so secrets are never encrypted directly with a static key.
2. **Zero-Knowledge Architecture & Anti-IDOR RBAC** ensuring administrators cannot view users' plaintext secrets and users cannot access unowned resources.
3. **Defense-in-Depth Authentication** with Argon2id password hashing, rate limiting, and automatic 15-minute account lockouts.
4. **Tamper-Evident Cryptographic Audit Logging** utilizing SHA-256 hash chaining and HMAC signatures to mathematically prove log integrity.

---

## 2. Core Cryptographic Architecture

### Two-Tier Envelope Encryption Workflow
Rather than encrypting all records with a single database-wide key, this platform employs a separation of concerns between Master Keys (Key Encryption Keys - KEKs) and transient Data Encryption Keys (DEKs):

```
Write Secret Flow:
[Plaintext Secret] + [Transient 256-bit DEK] ──(AES-256-GCM)──> [Ciphertext] + [Auth Tag] + [IV]
                                      │
                         [Master Key (KEK)] ──(AES-256-GCM)──> [Wrapped DEK] + [Tag] + [IV]
                                                                          │
                                                                   [Plaintext DEK securely scrubbed]
                                                                          │
                                                         Database stores: Wrapped DEK + Ciphertext + Nonces + Tags
```

- **DEK (Data Encryption Key)**: A unique, cryptographically random 256-bit symmetric key (`AESGCM.generate_key(256)`) generated in-memory per secret. Scrubbed immediately after use.
- **KEK (Key Encryption Key)**: Master key stored wrapped under the server's root environmental key (`SERVER_ROOT_KEK`).
- **AES-256-GCM Authenticated Encryption**: Every operation generates a fresh 96-bit (12-byte) initialization vector (nonce) and outputs a 128-bit (16-byte) authentication tag, guaranteeing confidentiality and cryptographic integrity.

---

## 3. Role-Based Access Control (RBAC) Matrix

| Endpoint | Method | Unauthenticated / Guest | Standard User | Security Auditor | Administrator |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `/api/v1/auth/register` | POST | **Allowed** | Denied | Denied | Denied |
| `/api/v1/auth/login` | POST | **Allowed** | Denied | Denied | Denied |
| `/api/v1/secrets` | GET | 401 Unauthorized | **Allowed (Own Only)** | 403 Forbidden | 403 Forbidden *(Zero-Knowledge)* |
| `/api/v1/secrets/{id}` | GET | 401 Unauthorized | **Allowed (Own Only)** | 403 Forbidden | 403 Forbidden *(Zero-Knowledge)* |
| `/api/v1/secrets` | POST | 401 Unauthorized | **Allowed** | 403 Forbidden | 403 Forbidden |
| `/api/v1/secrets/{id}` | DELETE | 401 Unauthorized | **Allowed (Own Only)** | 403 Forbidden | 403 Forbidden *(Zero-Knowledge)* |
| `/api/v1/keys` | POST | 401 Unauthorized | 403 Forbidden | 403 Forbidden | **Allowed (Full Control)** |
| `/api/v1/keys/{id}/rotate` | POST | 401 Unauthorized | 403 Forbidden | 403 Forbidden | **Allowed (Full Control)** |
| `/api/v1/audit/logs` | GET | 401 Unauthorized | 403 Forbidden | **Allowed** | **Allowed** |
| `/api/v1/audit/verify` | POST | 401 Unauthorized | 403 Forbidden | **Allowed** | **Allowed** |

> **Anti-IDOR / Anti-BOLA Guarantee**: All secret operations query `WHERE id = :secret_id AND owner_id = :session_user_id`. Even administrators cannot decrypt or read secret payloads without the user's specific context.

---

## 4. Tamper-Evident Audit Trail (Cryptographic Chaining)

Every security and cryptographic event is appended to an immutable audit chain:
- **Hash Chaining**: `previous_record_hash = SHA-256(previous_record_hash || timestamp || actor_id || action || resource_id)`
- **HMAC Signature**: `record_hmac = HMAC-SHA256(AUDIT_HMAC_SECRET, record_string)`
- **Verification Endpoint (`/api/v1/audit/verify`)**: Iterates through the audit chain, independently recomputing all SHA-256 hashes and HMAC tags. If any record in SQLite was modified or deleted, the audit chain verification immediately pinpoints the exact tampered row.

---

## 5. Live Defense Scenarios (Burp Suite & Forensics)

1. **Direct SQLite Inspection**: Proves zero plaintext at rest. High-entropy base64 ciphertext, IVs, and tags are stored.
2. **IDOR Privilege Escalation Attack**: Intercepting a `/api/v1/secrets/{id}` request with Burp Suite and replacing the ID with another user's secret yields a strict `403 Forbidden` / `404 Not Found`.
3. **Ciphertext Bit-Flipping Integrity Test**: Modifying even a single character of stored ciphertext in SQLite causes the AES-GCM tag verification to throw `cryptography.exceptions.InvalidTag`, preventing corrupt decryption.
4. **Brute-Force & Lockout Defense**: 5 consecutive failed login attempts trigger an immediate 15-minute account lockout logged in the cryptographic audit trail.

---

## 6. Project Layout

```
├── app/
│   ├── api/             # FastAPI routers (auth, secrets, keys, audit)
│   ├── core/            # Security configs, Argon2id, RBAC dependencies
│   ├── crypto/          # Envelope encryption (AES-256-GCM), HMAC audit chain
│   ├── models/          # SQLAlchemy ORM models & Pydantic schemas
│   ├── config.py        # Settings management via python-dotenv
│   └── main.py          # FastAPI application factory & middleware
├── docs/                # Threat models (STRIDE) and architecture specs
├── tests/               # Pytest suite (crypto, RBAC/IDOR, audit verification)
├── .env.example
├── .gitignore
├── requirements.txt
└── README.md
```

---

## 7. Getting Started

### Prerequisites
- Python 3.11+ (Python 3.13 tested)
- Git

### Installation
```bash
# Clone the repository
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>

# Install dependencies
pip install -r requirements.txt

# Copy configuration
copy .env.example .env

# Run unit and security test suite
pytest -v

# Start the KMS Vault API server
uvicorn app.main:app --reload --port 8000
```
Once started, explore the interactive OpenAPI / Swagger UI at `http://127.0.0.1:8000/docs`.
