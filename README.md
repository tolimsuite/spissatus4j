<p align="center">
  <img src="assets/spissatus4j.svg" alt="spissatus4j" width="128">
</p>

<h1 align="center">spissatus4j</h1>

<p align="center">
  <strong>Cryptographic engineering, safely packaged.</strong>
</p>

<p align="center">
  A Java 25 library that wraps JCA and Bouncy Castle into a stable, policy-driven, fail-closed API.<br>
  Keys, envelopes, providers, GM/T algorithms and optional Spring Boot integration — without inventing primitives.
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <img alt="Java 25" src="https://img.shields.io/badge/Java-25-orange.svg">
  <img alt="Gradle 9.9" src="https://img.shields.io/badge/Gradle-9.9-02303A.svg">
  <img alt="Bouncy Castle 1.86" src="https://img.shields.io/badge/Bouncy_Castle-1.86-7A3E00.svg">
  <img alt="Version 0.1.0" src="https://img.shields.io/badge/version-0.1.0-success.svg">
</p>

<p align="center">
  <a href="README.md"><strong>English</strong></a> · <a href="README.zh.md">简体中文</a>
</p>

<p align="center">
  <a href="#installation">Installation</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="CONTRIBUTING.md">Contributing</a> ·
  <a href="CHANGELOG.md">Changelog</a> ·
  <a href="LICENSE">License</a>
</p>

## What is spissatus4j?

spissatus4j is an **engineering wrapper library**, not a new cryptography. It provides one API over mature
JCA and Bouncy Castle implementations, with safe defaults and explicit operational boundaries.

It is meant to be used as a dependency by Java applications. The core is a library: it does not start a server,
does not expose HTTP endpoints and can be assembled without Spring.

## Why spissatus4j

- **Safe defaults.** AES-256-GCM, ChaCha20-Poly1305 and SM4-GCM are first-class; ECB, DES, RC4, MD5 and SHA-1
  are denied by default; RSA signature keys must be at least 2048 bits.
- **Fail-closed.** Failed self-checks, unavailable policy sources, nonce reuse and broken runtime invariants
  stop operations instead of silently downgrading.
- **Real key lifecycle.** State machine, usage isolation, rotation, retention, wrapping, import/export and destruction.
- **Authenticated everywhere.** Non-AEAD modes are wrapped with Encrypt-then-MAC; verification happens before decryption.
- **Stable contracts.** Applications depend on `spissatus4j-contract`; providers are replaceable through SPI.

## Architecture

```text
                    ┌──────────────────────────────────────────────┐
  Application  ───▶ │ spissatus4j-contract                         │
                    │ facade · values · enums · exceptions · SPI   │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │ spissatus4j-core                             │
                    │ builder · fail-closed runtime · policy        │
                    │ registry · self-check · stream orchestration  │
                    └───────┬───────────────┬──────────────────────┘
                            │               │
          ┌─────────────────▼───┐       ┌───▼─────────────────────┐
          │ spissatus4j-crypto  │       │ spissatus4j-key         │
          │ JCA algorithms      │       │ lifecycle · providers   │
          └─────────┬───────────┘       └─────────────────────────┘
                    │
        ┌───────────┴────────────┐
        ▼                        ▼
 spissatus4j-bouncycastle   spissatus4j-gm
 BC/FIPS providers          SM2 · SM3 · SM4

 Supporting modules: spissatus4j-envelope, spissatus4j-policy,
 spissatus4j-spring-boot-starter (optional).
```

The core depends only on `contract`. Concrete providers register through `SpissatusModule` /
`AlgorithmProvider`; the default builder discovers them from the classpath.

## Repository layout

| Module | Purpose |
| --- | --- |
| `spissatus4j-contract` | Stable API, value objects, sealed exceptions and SPI |
| `spissatus4j-core` | Facade, builder, fail-closed runtime, registry and default policy |
| `spissatus4j-crypto` | JCA providers: AEAD, Encrypt-then-MAC, hashes, MACs, signatures, KDFs, streams |
| `spissatus4j-key` | Key state machine, providers, rotation, wrapping, import/export, destruction |
| `spissatus4j-envelope` | Self-describing TLV/JSON ciphertext envelopes |
| `spissatus4j-policy` | Algorithm, usage, access, tenant and compliance policy |
| `spissatus4j-bouncycastle` | Bouncy Castle provider, FIPS routing and interop checks |
| `spissatus4j-gm` | SM2/SM3/SM4 provider and GM/T test vectors |
| `spissatus4j-spring-boot-starter` | **Optional** Spring Boot 4 auto-configuration and CLI |
| `gradle/libs.versions.toml` | Single source of dependency versions |
| `assets/spissatus4j.svg` | Project logo |

## Requirements

- JDK 25
- Gradle Wrapper 9.9 (included)
- No application server or database is required to use the library

## Installation

```groovy
dependencies {
    implementation 'cn.tolim.spissatus4j:spissatus4j-contract:0.1.0'
    implementation 'cn.tolim.spissatus4j:spissatus4j-core:0.1.0'
    implementation 'cn.tolim.spissatus4j:spissatus4j-crypto:0.1.0'
    implementation 'cn.tolim.spissatus4j:spissatus4j-key:0.1.0'
    implementation 'cn.tolim.spissatus4j:spissatus4j-envelope:0.1.0'
    implementation 'cn.tolim.spissatus4j:spissatus4j-policy:0.1.0'
    implementation 'cn.tolim.spissatus4j:spissatus4j-bouncycastle:0.1.0'
    implementation 'cn.tolim.spissatus4j:spissatus4j-gm:0.1.0'
}
```

Optional add-on:

```groovy
// Spring Boot 4 auto-configuration + CLI
implementation 'cn.tolim.spissatus4j:spissatus4j-spring-boot-starter:0.1.0'
```

## Quick start

```java
CallerContext caller = CallerContext.system();
try (Spissatus facade = SpissatusBuilders.builder()
        .discoverModules(true)
        .failClosed(true)
        .build()) {

    KeyDescriptor key = facade.keyManager().generate(
        KeyGenerationRequest.builder(KeyType.AES, AlgorithmId.AES_GCM,
                Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT))
            .keyId(KeyId.of("order-aes"))
            .tenantId(caller.tenantId())
            .build(), caller);

    byte[] plaintext = "hello".getBytes(StandardCharsets.UTF_8);
    Envelope envelope = facade.encryptToEnvelope(
        EncryptRequest.builder(AlgorithmId.AES_GCM, key.keyId(), plaintext, caller).build(),
        EnvelopeFormat.JSON, BinaryEncoding.BASE64);

    byte[] encoded = facade.envelopeService().encode(envelope, envelope.format());
    byte[] decrypted = facade.decryptEnvelope(encoded, caller);
}
```

The default key manager uses an in-memory provider for development. Production deployments should configure
`file` or `keystore` storage, or implement a `KeyProvider` for KMS/Vault/HSM.

## Unified encrypt / decrypt

`Spissatus.encrypt(UnifiedEncryptRequest)` adds a single entry point that selects **one** primary
algorithm from the installed, compliant, authorized and key-compatible capabilities. It is
**capability aggregation**, not repeated encryption with every algorithm, and it never negotiates or
downgrades on decrypt.

```java
UnifiedEncryptionResult result = facade.encrypt(
    UnifiedEncryptRequest.builder(KeyId.of("order-aes"), plaintext, caller)
        .profile(SelectionProfile.AUTO_AEAD)
        .aad(AAD.ofUtf8("order-context"))
        .format(EnvelopeFormat.JSON)
        .encoding(BinaryEncoding.BASE64)
        .build());

byte[] encoded = facade.envelopeService()
    .encode(result.envelope(), result.envelope().format());
byte[] decrypted = facade.decrypt(
    UnifiedDecryptRequest.builder(encoded, caller).build());
```

- **Selection**: explicit algorithm, named suite, ordered candidate list, or a profile. The selector
  filters `PROHIBITED`/`UNKNOWN`/compliance-disallowed/provider-unavailable/key-incompatible
  candidates and records a bounded `SelectionReport`; the crypto service then performs exactly one
  `PolicyEngine.evaluate` for the selected key. A policy denial is final: there is no fallback.
- **Envelopes**: unified encryption produces a **v2** envelope for symmetric **AEAD/EtM** algorithms.
  `headerHash` is a SHA-256 binding of the version, algorithm, key id, creation time, salt/KDF
  metadata and attributes; the cipher uses a domain-separated effective AAD built from that hash and
  the caller AAD. For these symmetric envelopes, tampering with routing or metadata fails before
  decryption. Asymmetric algorithms remain available through the low-level API and v1 envelopes;
  they are not valid v2 envelope algorithms. Unified decrypt rejects legacy v1 envelopes unless
  `allowLegacyV1(true)` is set (and the operator setting also allows it); freshness checks require v2.
- **Key version**: `keyVersion` is deliberately not part of `headerHash`; a wrong version is normally
  detected because the key material differs and the tag fails. If version substitution matters,
  pin it with `expectedKeyVersion`. Reused/imported key material that is identical across versions
  cannot be distinguished by the tag alone.
- **Profiles**: `AUTO_AEAD` (default), `AUTO_AEAD_THEN_ETM` (explicit opt-in for EtM-wrapped block
  modes), `FIPS_AEAD`, `GM_AEAD`, `GM_HYBRID_AEAD`. Automatic profiles never select asymmetric
  algorithms, experimental/deprecated algorithms, or weaker modes. `selectionCapabilities()` lists
  only profiles valid for the active compliance mode.
- **Keys**: `keyId` or an explicit `candidateKeyIds` list. Automatic tenant-wide key listing is not
  performed in this version. Only ACTIVE keys protect new data; DEACTIVATED keys remain usable for
  historical decryption. A missing candidate key is recorded and the ordered list continues;
  provider failures abort.
- **Capabilities**: `facade.selectionCapabilities()` reports installed/compliant/available
  algorithms without exposing provider types.
- **Settings**: `spissatus.selection.profile`, `preferred-algorithms`, `allow-deprecated`,
  `allow-experimental`, `allow-family-reuse`, `allow-legacy-v1`, `max-candidates`. The `allow-*`
  settings are operator ceilings: a request flag must also be set. CLI flags set both sides.
- **CLI migration**: `spissatus4j decrypt` now uses the unified entry and rejects v1 envelopes by
  default; pass `--allow-legacy-v1` (which also enables the operator ceiling for that process) or
  re-encrypt data as v2. The library `decryptEnvelope` still accepts v1 for compatibility.

## Spring Boot starter (optional)

```yaml
spissatus:
  fail-closed: true
  compliance-mode: STANDARD        # STANDARD | FIPS | GM | GM_HYBRID
  keys:
    provider: file                 # memory | file | environment | keystore | provided
    file-directory: /var/lib/app/keys
    master-password: ${SPISSATUS_MASTER_PASSWORD}
  policy:
    allow-anonymous: false
    allowed-tenants: [tenant-a]
    rate-limit-per-minute: 6000
  self-check:
    on-startup: true
    failure-fails-startup: true
  provider:
    jca: true
    bouncycastle: true
    gm: true
    fips: false
```

The starter registers a `Spissatus` bean and a `SpissatusLogSanitizer` bean. It does not start a web server
or expose HTTP endpoints.

## Algorithms

| Family | JCA | Bouncy Castle | GM/T |
| --- | --- | --- | --- |
| AEAD | AES-GCM, ChaCha20-Poly1305 | AES-GCM, ChaCha20-Poly1305 | SM4-GCM |
| Block (EtM only) | AES-CBC/CTR/CFB/OFB | — | SM4-CBC/CTR |
| Asymmetric | RSA-OAEP, RSA PKCS#1 v1.5 | RSA-OAEP, ECIES | SM2 |
| Hash | SHA-256/384/512, SHA3-256/512 | SHAKE128/256, BLAKE2b | SM3 |
| MAC | HMAC-SHA256/384/512 | HMAC, CMAC-AES | HMAC-SM3 |
| Signature | Ed25519, Ed448, ECDSA P-256/P-384, RSA-PSS | Ed448, ECDSA, RSA-PSS, RSA PKCS#1 v1.5 | SM2 |
| KDF | PBKDF2, HKDF | Argon2id, scrypt, bcrypt, PBKDF2, HKDF | — |
| Stream | Chunked AEAD (12-byte nonce) | — | — |

Post-quantum identifiers (`ML-KEM-768`, `ML-DSA-65`) and the `Kem`/`HybridKem` contracts are reserved and
denied by default until explicitly enabled.

## Security model

- **One policy decision per operation**, including rate limiting and tenant checks.
- **Nonce tracking** for every AEAD/EtM encryption and every stream base nonce.
- **Encrypt-then-MAC** for AES-CBC/CTR/CFB/OFB and SM4-CBC/CTR, with constant-time verification before decrypt.
- **Generic authentication failures** that do not distinguish padding, tag and key errors.
- **Key state and usage isolation**: only ACTIVE keys protect; DEACTIVATED keys only process historical data.
- **FIPS mode** selects only providers declaring `fipsCapable()`; startup fails without a FIPS provider.
- **Self-check** validates providers at startup; failure is fail-closed.
- **Extension trust** is anchored on exact module class names, never self-declared module ids.

## Build and test

```bash
./gradlew clean build              # compile, tests, package checks, jars
./gradlew test                     # all module tests
./gradlew checkPackageNames        # package naming gate
```

All modules must keep the `cn.tolim.spissatus4j.` package prefix; the `checkPackageNames` task enforces it.
Jars carry `Automatic-Module-Name` metadata.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Use short-lived branches, conventional
commit messages, and keep dependency versions in [`gradle/libs.versions.toml`](gradle/libs.versions.toml).

## Security

Please do not disclose vulnerabilities in public issues. Use GitHub's private security advisory on
<https://github.com/tolimsuite/spissatus4j> or contact TOLIM Technologies Pte. Ltd. privately with a
reproduction and affected versions. Never commit credentials, private keys or production data.

## License

Copyright 2026 TOLIM Technologies Pte. Ltd.

Licensed under the [Apache License, Version 2.0](LICENSE). You may not use this project except in compliance
with the License. See [NOTICE](NOTICE) for attribution.
