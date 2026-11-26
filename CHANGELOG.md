# Changelog

All notable changes to spissatus4j are documented here.

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
