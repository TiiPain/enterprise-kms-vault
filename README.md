# Enterprise KMS & Secret Vault

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Cryptography](https://img.shields.io/badge/Cryptography-AES--256--GCM-red.svg)](https://cryptography.io/)
[![Security](https://img.shields.io/badge/Auth-Argon2id-orange.svg)](https://en.wikipedia.org/wiki/Argon2)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An authenticated, production-grade **Key Management Service (KMS) & Secret Vault** built with Python and FastAPI. Patterned after AWS KMS and HashiCorp Vault, the service implements **two-tier envelope encryption**, **zero-knowledge role-based access control (RBAC)**, and **tamper-evident audit logging**.

---

## Architecture & How It Works

### Two-Tier Envelope Encryption
Rather than encrypting all records under a static, shared database key, the vault uses an envelope encryption model that cryptographically decouples data encryption from key management:

```
[Plaintext Secret] + [Transient 256-bit DEK] ──(AES-256-GCM)──> [Ciphertext] + [Auth Tag] + [IV]
                                      │
                         [Master Key (KEK)] ──(AES-256-GCM)──> [Wrapped DEK] + [Tag] + [IV]
                                                                          │
                                                                   [DEK scrubbed from memory]
                                                                          │
                                                         Database stores: Ciphertext, Wrapped DEK, IVs & Tags
```

1. **Data Encryption Key (DEK)**: A fresh 256-bit symmetric key generated in memory per secret write. It never touches persistent storage in plaintext.
2. **Key Encryption Key (KEK)**: Long-lived Master Keys stored encrypted under the server's root environmental key.
3. **Payload Protection**: Authenticated encryption via **AES-256-GCM** ensures that both confidentiality and cryptographic integrity are guaranteed. Any bit-level modification to stored ciphertext or tags causes decryption to immediately fail.

---

## Key Features

* **Authenticated Encryption (AES-256-GCM)**: Each secret payload is encrypted with a unique 96-bit random IV and verified against a 128-bit authentication tag.
* **Defense-in-Depth Authentication**: Passwords hashed using memory-hard **Argon2id** with automatic account lockouts after consecutive failed attempts.
* **Zero-Knowledge Access Control (Anti-IDOR)**: Strict object-level ownership checks. Vault administrators manage keys and user statuses but have zero access to read or decrypt user secrets.
* **Tamper-Evident Audit Trails**: Audit events are cryptographically chained using SHA-256 hashes and signed with HMAC-SHA256, allowing mathematical proof of audit log integrity.

---

## Project Structure

```
├── app/
│   ├── api/             # REST endpoints (auth, secrets, keys, audit)
│   ├── core/            # Security configs, Argon2id hashing, RBAC guards
│   ├── crypto/          # Envelope encryption engine & audit hash-chaining
│   ├── models/          # SQLAlchemy ORM models & Pydantic validation schemas
│   ├── config.py        # Centralized environment settings
│   └── main.py          # FastAPI application entrypoint & middleware
├── tests/               # Security and cryptographic unit tests
├── .env.example         # Configuration template
├── requirements.txt     # Python dependencies
└── README.md
```

---

## Quickstart

### 1. Prerequisites
* Python 3.11+
* Git

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/TiiPain/enterprise-kms-vault.git
cd enterprise-kms-vault

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
copy .env.example .env
```

### 3. Run Test Suite
```bash
pytest -v
```

### 4. Start the API Server
```bash
uvicorn app.main:app --reload --port 8000
```

The interactive OpenAPI documentation will be available at `http://127.0.0.1:8000/docs`.
