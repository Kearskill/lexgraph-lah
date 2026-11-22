# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.2.x` (`main`) | Yes |
| `0.1.x` | Security fixes via upgrade to `0.2.x` |

---

## Threat Model & Architectural Security Boundaries

`lexgraph-lah` is designed as a multi-layered compliance engine where untrusted contract documents, external LLM calls, and multi-tenant API traffic are strictly isolated:

### 1. Pre-AST Document Firewall & Archive Guards (`src/lexgraph_lah/security/doc_firewall.py`)
All uploaded `.docx`, `.pdf`, and raw text contracts are inspected at zero LLM token cost **before** AST parsing or prompt assembly:
- **OOXML Zip-Bomb & Path Traversal Defense (`validate_zip_archive_safety`)**: Enforces bounded uncompressed byte ceilings (`DOCX_MAX_UNCOMPRESSED_BYTES`), streaming >64 KB compression-ratio limits (`DOCX_MAX_COMPRESSION_RATIO`), maximum entry counts (`DOCX_MAX_ENTRIES`), and rejection of `../`, drive-letter, or absolute archive paths prior to XML unpacking.
- **Hidden OOXML Layer Quarantine**: Strips and flags `<w:vanish/>`, `<w:webHidden/>`, micro-sized fonts (`<= 1pt`), near-white text (`#FFFFFF` / `#FEFEFE`), embedded VBA macros / ActiveX binaries (`vbaProject.bin`), suspicious `customXml/*.xml` parts, and hidden comments while keeping legitimate visible clauses and `<w:trackRevisions/>`.
- **PDF & Plain-Text Prompt Injection Controls**: Detects and quarantines PDF invisible rendering mode (`3 Tr`), zero/micro-point fonts, off-canvas `Tm`/`Td` coordinates, bilingual English / Bahasa Melayu indirect prompt injection instructions, and statutory spoof overrides (`"Abaikan semua peruntukan..."`, `"Ignore previous statutory rules..."`).

### 2. Pre-Flight Malaysian PII Scrubber & Cross-Worker Vault (`src/lexgraph_lah/middleware/pii_scrubber.py`)
- **Pre-LLM Deterministic Masking (`<50ms` SLA)**: Pre-compiled regexes replace Malaysian MyKad/NRIC (`[MYKAD_01]`), passports (`[PASSPORT_01]`), phone numbers (`[PHONE_MY_01]`), email addresses (`[EMAIL_01]`), SSM registration numbers (`[SSM_REG_01]`), LHDN TINs (`[TIN_MY_01]`), KWSP/EPF numbers (`[KWSP_01]`), PERKESO/SOCSO IDs (`[PERKESO_01]`), and Malaysian bank / DuitNow numbers (`[BANK_MY_01]`) before external Gemini calls or OpenTelemetry span emission.
- **Cross-Worker Encrypted Session Vault (`EncryptedPIISessionStore`)**: Token re-hydration mappings for `/compliance/check` -> `/compliance/export-docx` are encrypted at rest with **AES-256-GCM**, unique 96-bit nonces per write, strict TTL expiration (`PII_VAULT_TTL_SECONDS`), and authenticated additional data (`AAD = f"{tenant_id}:{audit_session_id}"`) backed by `memory`, `sqlite` (WAL mode), or `redis`.

### 3. Enterprise Authentication, RBAC & Rate Limiting (`src/lexgraph_lah/security/auth.py`)
- **Fail-Closed Production Guard**: If `ENV=production` (or `APP_ENV=production`) while `AUTH_MODE=disabled`, `EnterpriseSecurityMiddleware` fails closed with HTTP `503` on all non-`/health` routes.
- **Credential Verification (`AUTH_MODE=api_key|jwt`)**:
  - `api_key`: Compares SHA-256 hex digests of presented credentials against `AUTH_API_KEYS_JSON` in constant time (`hmac.compare_digest`).
  - `jwt`: Verifies compact `HS256`, `EdDSA` (Ed25519), or `RS256` Bearer tokens against `JWT_SECRET` / `JWT_PUBLIC_KEY_PEM`, validating `exp`, `nbf`, `iss`, `aud`, and explicitly rejecting `"alg": "none"`.
- **RBAC & Anti-Spoofing**: Enforces `viewer` (read-only REST, `/api/v1/attestation/verify`, and discovery-only MCP methods), `auditor`, and `admin` roles across REST, SSE (`/compliance/stream`), and JSON-RPC (`POST /mcp`). Rejects mismatched `X-Tenant-ID` headers (`403`) to prevent cross-tenant spoofing.
- **Sliding-Window Rate Limiting**: Optional per-`(tenant_id, client_ip)` limiter returning HTTP `429` with `Retry-After`, `X-RateLimit-Limit`, and `X-RateLimit-Remaining` headers.

### 4. Tamper-Evident & Ed25519 Signed Attestation Ledger (`src/lexgraph_lah/security/attestation_ledger.py`)
- Every audit manifest is anchored into an append-only **SHA-256 hash chain** stored in SQLite WAL or PostgreSQL (`ATTESTATION_BACKEND=sqlite|postgres`) and signed at every chain tip using **Ed25519** (`ATTESTATION_ED25519_PRIVATE_KEY_PEM` or a pluggable `AttestationSigner`).
- External auditors can fetch the public verification key at `GET /api/v1/attestation/public-key` and verify full document, statutory snapshot, hash-chain, and Ed25519 signature integrity via `POST /api/v1/attestation/verify`.

---

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities, bypasses of `doc_firewall.py` / `EnterpriseSecurityMiddleware`, or credential leaks.

1. Report privately via GitHub Security Advisories (**Security -> Advisories -> Report a vulnerability**) on the repository.
2. Include a minimal reproduction payload or endpoint trace, expected vs. actual security boundary behavior, and affected module path.
3. Initial acknowledgment is targeted within 72 hours, followed by coordinated remediation and disclosure in `CHANGELOG.md`.
