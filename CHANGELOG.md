# Changelog

All notable changes to spissatus4j are documented here.

## [Unreleased]

### Added

- Unified `Spissatus.encrypt(UnifiedEncryptRequest)` / `decrypt(UnifiedDecryptRequest)` entry point:
  deterministic selection of one primary algorithm from installed, compliant, authorized and
  key-compatible capabilities; ordered candidate lists, named suites and `AUTO_AEAD` /
  `AUTO_AEAD_THEN_ETM` / FIPS / GM profiles.
- Envelope version 2 with a SHA-256 `headerHash` binding version, algorithm, key id, creation time,
  salt/KDF metadata and attributes; effective AAD is domain-separated and reconstructed on decrypt.
- Selection hints on `PolicyEngine` (non-authoritative, no rate-limit side effects); selection
  reports, capabilities view, audit events and bounded metrics.
- Spring Boot `spissatus.selection.*` properties and CLI unified encrypt/decrypt, `--keys`,
  `--suite`, `--profile` and `--allow-legacy-v1`.
- ChaCha20-Poly1305 key generation in the default key manager.

### Security

- V2 envelope metadata tampering is detected before decryption; v1 envelopes are rejected by the
  unified entry unless explicitly allowed.
- Unified decryption maps tag, padding and ciphertext failures to a generic authentication error.
- One authoritative policy decision per unified operation; policy denials never fall back to another
  algorithm or key.
- FIPS/GM routing filters by compliance and provider capability; `Capabilities.fipsAvailable` now
  reflects installed FIPS-capable providers.
- Stream metrics use bounded algorithm tags (`unknown` for unregistered ids).

## [0.1.0] - 2026-11-26

Initial public release.

### Added

- Contract-first facade, value objects, sealed exception hierarchy, SPI and compliance contracts.
- Fail-closed core runtime: builder, startup self-check, constant-time comparison, redaction,
  nonce-reuse detection, extension registry and module trust.
- JCA provider: AES-GCM, ChaCha20-Poly1305, AES-CBC/CTR/CFB/OFB with Encrypt-then-MAC, RSA-OAEP,
  RSA PKCS#1 v1.5, Ed25519, Ed448, ECDSA, RSA-PSS, SHA-2/SHA-3, HMAC, PBKDF2, HKDF and chunked AEAD streams.
- Key lifecycle: state machine, usage and tenant isolation, rotation, retention, wrapping, import/export,
  memory/file/environment/keystore providers, and destruction.
- Self-describing TLV/JSON envelopes with strict parsing, version policy and text encodings.
- Policy engine: algorithm, usage, access, tenant and compliance rules with strictest-wins merging and
  fail-closed rate limiting.
- Bouncy Castle provider: FIPS routing, Argon2id, scrypt, bcrypt, SHAKE, BLAKE2b, ECIES, CMAC-AES and
  RSA PKCS#1 v1.5 signatures.
- GM/T provider: SM2 encryption/signature/wrapping, SM3, HMAC-SM3, SM4-GCM/CBC/CTR with official vectors.
- Optional Spring Boot 4 starter: auto-configuration, properties, log sanitizer and CLI.
- Apache License 2.0, README/README.zh, CONTRIBUTING/CONTRIBUTING.zh and version catalog.

### Security

- Default denial of ECB, DES, RC4, MD5, SHA-1 and experimental algorithms.
- Generic authentication failures; verify-before-decrypt for all Encrypt-then-MAC modes.
- Nonce reuse detection, FIPS provider gating and exact-class module trust.
