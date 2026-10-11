# Authenticated Enterprise KMS & Secret Vault

[![Python](https://img.shields.io/badge/Python-3.11%2B%20%7C%203.14-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Cryptography](https://img.shields.io/badge/Cryptography-AES--256--GCM-red.svg)](https://cryptography.io/)
[![Password Hashing](https://img.shields.io/badge/Auth-Argon2id-orange.svg)](https://en.wikipedia.org/wiki/Argon2)
[![Test Suite](https://img.shields.io/badge/Tests-75%2F75%20Passing%20(100%25)-brightgreen.svg)](https://docs.pytest.org/)
[![Track](https://img.shields.io/badge/ING5%20SSIRE-Track%2002%3A%20Protect-purple.svg)](https://github.com/TiiPain/enterprise-kms-vault)

An authenticated, production-grade **Key Management Service (KMS) & Secret Vault** designed under a strict **Zero-Trust** and **Zero-Knowledge** operational architecture. Patterned after AWS KMS and HashiCorp Vault, the service implements **Two-Tier Envelope Encryption (AES-256-GCM)**, **Argon2id password hashing with brute-force lockout defenses**, **Anti-IDOR object-level authorization**, and **cryptographically tamper-evident SHA-256/HMAC-SHA256 audit chaining**.

Developed for **ING5 SSIRE (Class of 2026)** — *Art of Protecting Secrets* by **Ahmed Amine Ghenimi** & **Abdallah Dridi**.

---

## 🛡️ Core Security Architecture & Pillars

```
[ Plaintext Secret ] + [ Transient 256-bit DEK ] ──(AES-256-GCM)──> [ Ciphertext ] + [ Auth Tag ] + [ IV ]
                                        │
                           [ Master Key (KEK) ] ──(AES-256-GCM)──> [ Wrapped DEK ] + [ Tag ] + [ IV ]
                                                                             │
                                                                   [ DEK scrubbed from RAM ]
                                                                             │
                                                  Database Stores: Ciphertext, Wrapped DEK, IVs & Tags (0 Plaintext)
```

1. **Two-Tier Envelope Cryptography**:
   * Plaintext secret payloads are encrypted with ephemeral 256-bit Data Encryption Keys (DEKs) using **AES-256-GCM** (unique 96-bit random nonce + 128-bit authentication tag).
   * Transient DEKs are wrapped under a rotatable Master Key (KEK), which is wrapped under a Root KEK.
   * Plaintext DEKs and KEKs are scrubbed immediately from RAM.
   * Zero plaintext ever touches persistent storage.
2. **Anti-IDOR & Zero-Knowledge RBAC**:
   * Strict object-level ownership checks enforce tenant isolation (`user_id == secret.owner_id`).
   * Vault Administrators have zero programmatic capability to read or decrypt user secrets.
3. **Defense-in-Depth Authentication & Lockout**:
   * Passwords hashed using memory-hard **Argon2id** ($m=64\text{ MB}, t=2, p=2$).
   * 5 consecutive failed login attempts trigger an automated **15-minute account lockout**.
4. **Tamper-Evident Cryptographic Audit Trail**:
   * Append-only event chaining: $H_i = \text{SHA-256}(H_{i-1} \parallel \text{timestamp} \parallel \text{actor} \parallel \text{action} \parallel \text{resource})$.
   * Every record is signed with an HMAC-SHA256 authenticity signature.
   * $O(N)$ integrity verifier mathematically detects altered, recomputed, or deleted records.
5. **Interactive Single-Page Security Console**:
   * Pure HTML5/Tailwind/vanilla ES6 dashboard served directly at `http://127.0.0.1:8000/`.
   * Live defense tabs for storage-at-rest inspection, bit-tampering attacks, and audit verification.

---

## 📁 Repository Structure

```
├── app/
│   ├── api/             # REST endpoints (auth, secrets, keys, audit, deps)
│   ├── core/            # Argon2id hashing, lockout defense, RBAC guards
│   ├── crypto/          # Envelope crypto engine & SHA-256/HMAC audit chain
│   ├── models/          # SQLAlchemy ORM models & Pydantic schemas
│   ├── static/          # Single-page Web UI security console (index.html)
│   ├── config.py        # Centralized settings & Root KEK loader
│   └── main.py          # FastAPI application, security headers & lifespan
├── docs/
│   ├── architecture_spec.md  # Formal technical & cryptographic specification
│   ├── threat_model.md       # STRIDE threat matrix & mitigation analysis
│   ├── test_cases.md         # Burp Suite interception & test payloads
│   └── oral_defense_guide.md # 5-minute live defense rehearsal & jury Q&A
├── scripts/
│   ├── demo_step1_inspect_db.py         # Oral Step 1: Storage at rest inspection
│   ├── demo_step2_idor_attack.py        # Oral Step 2: Anti-IDOR blocking (HTTP 403)
│   ├── demo_step3_bit_tamper_attack.py   # Oral Step 3: Bit-tamper InvalidTag failure (HTTP 400)
│   ├── demo_step4_brute_force_lockout.py # Oral Step 4: 5-strike brute-force lockout
│   └── demo_step5_tamper_audit_log.py   # Oral Step 5: Audit log tamper detection
├── tests/               # 75 automated security unit & integration tests
├── .env.example         # Production configuration template
├── requirements.txt     # Python dependencies
└── README.md            # Project documentation
```

---

## 🚀 Quickstart Guide

### 1. Prerequisites & Installation
* **Python 3.11+** (compatible through 3.14)
* **Git**

```bash
# Clone the repository
git clone https://github.com/TiiPain/enterprise-kms-vault.git
cd enterprise-kms-vault

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
```

### 2. Run the Full Security Test Suite
Verify all 75 cryptographic, authentication, RBAC, and API integration tests:

```bash
pytest -v
```
*(Result: **75 passed in 6.45s — 100% pass rate**)*

### 3. Launch the Application & Web Dashboard
```bash
uvicorn app.main:app --port 8000 --reload
```
* **Interactive Security Console**: Open [http://127.0.0.1:8000](http://127.0.0.1:8000)
* **Interactive OpenAPI Docs**: Open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## 🎯 5-Minute Live Oral Defense Demonstration

The repository includes standalone scripts to reproduce all 5 oral defense proofs for the jury:

| Oral Defense Step | Command | Demonstrated Security Control |
| :--- | :--- | :--- |
| **Step 1: Storage at Rest** | `python scripts/demo_step1_inspect_db.py` | Proves zero plaintext in SQLite; inspects raw AES-256-GCM ciphertexts and wrapped DEKs. |
| **Step 2: Anti-IDOR Attack** | `python scripts/demo_step2_idor_attack.py` | User B attempts to access User A's secret; blocked with `HTTP 403 Forbidden` and audited. |
| **Step 3: Bit-Tampering** | `python scripts/demo_step3_bit_tamper_attack.py` | Corrupts 1 byte in stored ciphertext; AES-GCM fails authentication with `InvalidTag` (`HTTP 400`). |
| **Step 4: Brute-Force Lockout** | `python scripts/demo_step4_brute_force_lockout.py` | Executes 5 failed logins; demonstrates automatic 15-minute account lockout and CPU protection. |
| **Step 5: Tamper Audit Trail** | `python scripts/demo_step5_tamper_audit_log.py` | Tampers with a database audit row; verifier flags mathematical HMAC and hash-chain failure. |

For the complete rehearsal script, slide timeline, and top 10 jury questions & answers, see [`docs/oral_defense_guide.md`](docs/oral_defense_guide.md).

---

## 📚 Technical Documentation Directory

* **[Architecture Specification](docs/architecture_spec.md)**: Deep dive into envelope cryptography, key lifecycle state machines, and mathematical formulations.
* **[STRIDE Threat Model](docs/threat_model.md)**: Exhaustive STRIDE evaluation, asset mapping, and residual risk assessment.
* **[Burp Suite Test Cases](docs/test_cases.md)**: Raw HTTP request payloads and step-by-step Burp Suite interception guide.
* **[Oral Defense Rehearsal Guide](docs/oral_defense_guide.md)**: Timed script, student role allocations, and jury Q&A cheat-sheet.

---

## 👥 Authors & Academic Context
* **Authors**: Ahmed Amine Ghenimi & Abdallah Dridi
* **Academic Program**: ING5 SSIRE (Cybersecurity Engineering) — Class of 2026
* **Course**: *Art of Protecting Secrets* (Track 02: Protect)
* **License**: MIT
