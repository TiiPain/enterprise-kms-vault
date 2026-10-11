# STRIDE Threat Model & Security Evaluation

**Project**: Authenticated Enterprise Key Management Service (KMS) & Secret Vault  
**Academic Program**: ING5 SSIRE (Class of 2026) — *Art of Protecting Secrets* (Track 02: Protect)  
**Authors**: Ahmed Amine Ghenimi & Abdallah Dridi  
**Repository**: [https://github.com/TiiPain/enterprise-kms-vault](https://github.com/TiiPain/enterprise-kms-vault)  

---

## 1. Threat Modeling Methodology

This document evaluates the security architecture of the Enterprise KMS & Secret Vault against adversarial threats using the **STRIDE** methodology (developed by Microsoft). The system is assessed across its primary trust boundaries, data flows, and persistent storage assets.

```
       [ Client Browser / Burp Suite ]
                      │
   ═══════════════════╪═══════════════════  [ Trust Boundary 1: External Network ]
                      ▼
            [ FastAPI Web Server ]
         (Argon2id, RBAC, Headers)
                      │
   ═══════════════════╪═══════════════════  [ Trust Boundary 2: Process Memory ]
                      ▼
         [ Envelope Crypto Engine ]
          (AES-256-GCM, Key Scrub)
                      │
   ═══════════════════╪═══════════════════  [ Trust Boundary 3: Storage at Rest ]
                      ▼
         [ SQLite Database Storage ]
      (Ciphertexts, Wrapped DEKs, Hashes)
```

### Risk Severity Rating (DREAD Alignment)
* **High**: Immediate impact on confidentiality or cryptographic integrity; remote exploitability.
* **Medium**: Local authorization bypass or targeted availability impairment.
* **Low**: Informational leakage or minor configuration discrepancies.

---

## 2. Comprehensive STRIDE Threat Matrix

| Threat ID | STRIDE Category | Target Asset | Attack Scenario / Vector | Severity | Implemented Countermeasure | Code Enforcement Reference |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- |
| **T-01** | **Spoofing** | User Identity / Auth Endpoint | Credential brute-forcing, dictionary attacks, and automated credential stuffing. | **High** | Password complexity policy + 5-attempt threshold triggering automated 15-minute account lockout. | [`app/core/security.py`](file:///c:/Users/TiiPain/Downloads/Enterprise_KMS_Vault/app/core/security.py#L40-L75), [`app/api/auth.py`](file:///c:/Users/TiiPain/Downloads/Enterprise_KMS_Vault/app/api/auth.py#L45-L75) |
| **T-02** | **Spoofing** | Session Management | Session prediction, token replay, or session fixation attacks. | **High** | 256-bit cryptographically secure session tokens generated via `secrets.token_urlsafe(32)` stored in memory/DB with strict expiration. | [`app/core/security.py`](file:///c:/Users/TiiPain/Downloads/Enterprise_KMS_Vault/app/core/security.py#L78-L95) |
| **T-03** | **Tampering** | Stored Secrets (Ciphertext) | Direct bit-flipping attack on ciphertext or modification of database rows by a malicious DBA. | **High** | Authenticated Encryption via `AES-256-GCM`. Decryption strictly validates 128-bit authentication tags; tag mismatch halts decryption and raises `InvalidTag`. | [`app/crypto/envelope.py`](file:///c:/Users/TiiPain/Downloads/Enterprise_KMS_Vault/app/crypto/envelope.py#L80-L105), [`app/api/secrets.py`](file:///c:/Users/TiiPain/Downloads/Enterprise_KMS_Vault/app/api/secrets.py#L188-L200) |
| **T-04** | **Tampering** | Audit Trail Log Entries | Attacker with database access modifies historical actions or deletes incriminating log rows. | **High** | Sequential SHA-256 hash chaining: $H_i = \text{SHA-256}(H_{i-1} \parallel \dots)$ signed with server-side HMAC-SHA256 signatures. $O(N)$ integrity verifier detects any modification or row deletion. | [`app/crypto/audit_chain.py`](file:///c:/Users/TiiPain/Downloads/Enterprise_KMS_Vault/app/crypto/audit_chain.py#L103-L166), [`app/api/audit.py`](file:///c:/Users/TiiPain/Downloads/Enterprise_KMS_Vault/app/api/audit.py#L45-L65) |
| **T-05** | **Repudiation** | Key Management & Secret Actions | User or administrator denies performing key generation, secret deletion, or unwrap requests. | **Medium** | Immutable append-only cryptographic audit logging recording UTC timestamp, actor ID, action type, and target resource ID. | [`app/crypto/audit_chain.py`](file:///c:/Users/TiiPain/Downloads/Enterprise_KMS_Vault/app/crypto/audit_chain.py#L65-L101) |
| **T-06** | **Information Disclosure** | Data at Rest (Database Leak) | Compromised database backup, lost laptop, or raw SQLite file theft exposing secret payloads. | **High** | Two-Tier Envelope Encryption. Zero plaintext in storage. Secret payloads encrypted with transient DEKs; DEKs wrapped under Master KEK; Master KEK wrapped under Root KEK. | [`app/crypto/envelope.py`](file:///c:/Users/TiiPain/Downloads/Enterprise_KMS_Vault/app/crypto/envelope.py#L45-L75), [`app/api/secrets.py`](file:///c:/Users/TiiPain/Downloads/Enterprise_KMS_Vault/app/api/secrets.py#L66-L94) |
| **T-07** | **Information Disclosure** | Host Process Memory | Cold-boot memory dump or core dump attack seeking unencrypted Data Encryption Keys. | **Medium** | Ephemeral DEKs are used transiently during the request lifecycle and explicitly scrubbed (`del transient_dek`, `del master_kek`). | [`app/api/secrets.py`](file:///c:/Users/TiiPain/Downloads/Enterprise_KMS_Vault/app/api/secrets.py#L75-L78), [`app/api/secrets.py`](file:///c:/Users/TiiPain/Downloads/Enterprise_KMS_Vault/app/api/secrets.py#L186-L188) |
| **T-08** | **Information Disclosure** | Client Browser / UI | Clickjacking attack embedding the KMS dashboard inside an invisible iframe to hijack user clicks. | **Medium** | Enterprise HTTP security headers injected globally: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and strict `Content-Security-Policy`. | [`app/main.py`](file:///c:/Users/TiiPain/Downloads/Enterprise_KMS_Vault/app/main.py#L82-L100) |
| **T-09** | **Denial of Service** | Authentication Endpoint | CPU exhaustion attack by flooding high-cost Argon2id hashing operations ($64\text{ MB}$, $t=2$). | **High** | Account lockout status is checked *before* performing Argon2 verification. Locked accounts are rejected immediately (`HTTP 403`), preventing CPU exhaustion. | [`app/api/auth.py`](file:///c:/Users/TiiPain/Downloads/Enterprise_KMS_Vault/app/api/auth.py#L48-L58) |
| **T-10** | **Elevation of Privilege** | Vault Secrets API | Insecure Direct Object References (IDOR/BOLA) where User B requests `/secrets/{alice_secret_id}`. | **High** | Mandatory server-side ownership guard `can_access_secret(user.id, secret.owner_id)`. Non-owners receive `HTTP 403 Forbidden` and the event is logged. | [`app/core/rbac.py`](file:///c:/Users/TiiPain/Downloads/Enterprise_KMS_Vault/app/core/rbac.py#L42-L55), [`app/api/secrets.py`](file:///c:/Users/TiiPain/Downloads/Enterprise_KMS_Vault/app/api/secrets.py#L158-L170) |
| **T-11** | **Elevation of Privilege** | Administrative Role | Rogue administrator attempts to inspect or decrypt confidential user secrets. | **High** | Zero-Knowledge RBAC policy strictly denies the `ADMIN` role from calling secret read, list, or unwrap endpoints (`HTTP 403`). | [`app/core/rbac.py`](file:///c:/Users/TiiPain/Downloads/Enterprise_KMS_Vault/app/core/rbac.py#L42-L55), [`app/api/secrets.py`](file:///c:/Users/TiiPain/Downloads/Enterprise_KMS_Vault/app/api/secrets.py#L37-L42) |

---

## 3. Attack Tree Analysis

### Attack Tree 1: Unauthorized Plaintext Secret Exfiltration
```
Goal: Obtain Plaintext Secret Payload
├── 1. Direct Database Extraction (Stolen keyvault.db)
│   ├── Stumble upon SQLite file on disk
│   └── Result: BLOCKED. Payload is AES-256-GCM ciphertext, DEK is wrapped under Master KEK.
├── 2. Insecure Direct Object Reference (IDOR) via API
│   ├── Authenticate as User B (Attacker)
│   ├── Enumerate User A's secret UUIDs: GET /api/v1/secrets/{alice_secret_id}
│   └── Result: BLOCKED. can_access_secret() evaluates false; returns HTTP 403 and records audit alert.
├── 3. Rogue Administrator Privilege Abuse
│   ├── Obtain valid Admin credentials
│   ├── Call GET /api/v1/secrets
│   └── Result: BLOCKED. Zero-Knowledge enforcement denies non-USER roles access to secret payloads.
└── 4. Ciphertext Bit-Flipping / Chosen-Ciphertext Attack
    ├── Modify stored SQLite bytes to alter plaintext output
    └── Result: BLOCKED. AES-256-GCM authentication tag verification fails; raises InvalidTag (HTTP 400).
```

### Attack Tree 2: Tampering with Historical Audit Logs
```
Goal: Cover Tracks by Altering Audit History
├── 1. Modify Stored Event Details (Action / Actor ID)
│   ├── Overwrite database row in SQLite
│   ├── Target row hash $H_i$ no longer matches computed hash
│   └── Result: FLAGGED. Continuous verification endpoint flags "Hash chain violation at record i".
├── 2. Recompute Downstream SHA-256 Hashes
│   ├── Attacker alters row $i$ and cascades hash calculation to row $N$
│   ├── Attacker lacks server-side secret AUDIT_HMAC_SECRET
│   └── Result: FLAGGED. HMAC-SHA256 signature verification fails at record $i$.
└── 3. Delete Incriminating Log Row
    ├── Attacker removes row $k$ entirely
    ├── Row $k+1$ expects $H_k$, but receives $H_{k-1}$
    └── Result: FLAGGED. Chain continuity broken; verifier flags broken sequence.
```

---

## 4. Residual Risks & Production Recommendations

1. **Root Key Security in Production**:
   * *Current State*: Root KEK loaded from server environment variable `ROOT_MASTER_KEY_HEX`.
   * *Production Hardening*: In enterprise production, the Root KEK should be backed by a Hardware Security Module (HSM) compliant with FIPS 140-2 Level 3 or cloud KMS (AWS KMS / GCP Cloud KMS / Azure Key Vault).

2. **Distributed Rate Limiting**:
   * *Current State*: Account lockouts tracked per-user in SQLite database rows.
   * *Production Hardening*: For multi-instance clustered deployments, place a distributed Redis token-bucket rate limiter in front of the API.
