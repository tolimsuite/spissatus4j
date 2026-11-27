<p align="center">
  <img src="assets/spissatus4j.svg" alt="spissatus4j" width="128">
</p>

<h1 align="center">spissatus4j</h1>

<p align="center">
  <strong>把密码学工程安全地封装好。</strong>
</p>

<p align="center">
  一个 Java 25 加密工程封装库：在 JCA 与 Bouncy Castle 之上提供稳定、策略驱动、fail-closed 的统一 API。<br>
  密钥、信封、Provider、国密算法与可选的 Spring Boot 集成 —— 不重造密码学原语。
</p>

<p align="center">
  <a href="LICENSE"><img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue.svg"></a>
  <img alt="Java 25" src="https://img.shields.io/badge/Java-25-orange.svg">
  <img alt="Gradle 9.9" src="https://img.shields.io/badge/Gradle-9.9-02303A.svg">
  <img alt="Bouncy Castle 1.86" src="https://img.shields.io/badge/Bouncy_Castle-1.86-7A3E00.svg">
  <img alt="Version 0.1.0" src="https://img.shields.io/badge/version-0.1.0-success.svg">
</p>

<p align="center">
  <a href="README.md">English</a> · <a href="README.zh.md"><strong>简体中文</strong></a>
</p>

<p align="center">
  <a href="#安装">安装</a> ·
  <a href="#快速开始">快速开始</a> ·
  <a href="#架构">架构</a> ·
  <a href="CONTRIBUTING.zh.md">参与贡献</a> ·
  <a href="CHANGELOG.zh.md">变更日志</a> ·
  <a href="LICENSE">许可证</a>
</p>

## spissatus4j 是什么

spissatus4j 是一个**工程封装型密码库**，不是一套新的密码学。它在成熟的 JCA 与 Bouncy Castle 实现之上
提供统一 API、默认安全参数与明确的运行边界。

它面向 Java 应用，以依赖库的形式使用。核心不会启动服务器、不会暴露 HTTP 端点，也不要求 Spring。

## 为什么选择 spissatus4j

- **默认安全。** 默认使用 AES-256-GCM、ChaCha20-Poly1305、SM4-GCM；默认拒绝 ECB、DES、RC4、MD5、SHA-1；
  RSA 签名密钥至少 2048 位。
- **fail-closed。** 自检失败、策略源不可用、Nonce 复用或运行时不变式被破坏都会拒绝操作，而不是静默降级。
- **完整的密钥生命周期。** 状态机、用途隔离、轮换、版本保留、包装、导入导出与销毁。
- **处处认证。** 非 AEAD 模式统一 Encrypt-then-MAC；先验证、后解密。
- **稳定契约。** 应用依赖 `spissatus4j-contract`，Provider 通过 SPI 可替换。

## 架构

```text
                    ┌──────────────────────────────────────────────┐
  应用        ───▶  │ spissatus4j-contract                         │
                    │ 门面 · 值对象 · 枚举 · 异常 · SPI            │
                    └──────────────────┬───────────────────────────┘
                                       │
                    ┌──────────────────▼───────────────────────────┐
                    │ spissatus4j-core                             │
                    │ 构建器 · fail-closed 运行时 · 策略  │
                    │ 注册表 · 自检 · 流式编排                     │
                    └───────┬───────────────┬──────────────────────┘
                            │               │
          ┌─────────────────▼───┐       ┌───▼─────────────────────┐
          │ spissatus4j-crypto  │       │ spissatus4j-key         │
          │ JCA 算法实现        │       │ 生命周期 · Provider     │
          └─────────┬───────────┘       └─────────────────────────┘
                    │
        ┌───────────┴────────────┐
        ▼                        ▼
 spissatus4j-bouncycastle   spissatus4j-gm
 BC/FIPS Provider           SM2 · SM3 · SM4

 支撑模块：spissatus4j-envelope、spissatus4j-policy、
 spissatus4j-spring-boot-starter（可选）。
```

core 只依赖 contract；具体 Provider 通过 `SpissatusModule` / `AlgorithmProvider` 注册，
默认构建器会从 classpath 自动发现。

## 仓库结构

| 模块 | 用途 |
| --- | --- |
| `spissatus4j-contract` | 稳定 API、值对象、密封异常与 SPI |
| `spissatus4j-core` | 门面、构建器、fail-closed 运行时、注册表与默认策略 |
| `spissatus4j-crypto` | JCA Provider：AEAD、Encrypt-then-MAC、哈希、MAC、签名、KDF、流式 |
| `spissatus4j-key` | 密钥状态机、Provider、轮换、包装、导入导出、销毁 |
| `spissatus4j-envelope` | 自描述 TLV/JSON 密文信封 |
| `spissatus4j-policy` | 算法、用途、访问、租户与合规策略 |
| `spissatus4j-bouncycastle` | Bouncy Castle Provider、FIPS 路由与互操作校验 |
| `spissatus4j-gm` | SM2/SM3/SM4 Provider 与 GM/T 测试向量 |
| `spissatus4j-spring-boot-starter` | **可选** Spring Boot 4 自动配置与 CLI |
| `gradle/libs.versions.toml` | 依赖版本唯一来源 |
| `assets/spissatus4j.svg` | 项目 Logo |

## 环境要求

- JDK 25
- Gradle Wrapper 9.9（仓库自带）
- 使用本库不需要应用服务器或数据库

## 安装

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

可选附加模块：

```groovy
// Spring Boot 4 自动配置 + CLI
implementation 'cn.tolim.spissatus4j:spissatus4j-spring-boot-starter:0.1.0'
```

## 快速开始

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

默认密钥管理器使用内存 Provider，适合开发与测试。生产环境应配置 `file` 或 `keystore` 存储，
或实现 KMS/Vault/HSM 的 `KeyProvider`。

## 统一加密 / 解密入口

`Spissatus.encrypt(UnifiedEncryptRequest)` 新增统一入口：从已安装、合规、已授权且与密钥兼容的
能力中选择**唯一主算法**。它是**能力聚合**，不是用所有算法重复加密，解密时也绝不协商或降级。

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

- **选择**：显式算法、命名套件、有序候选列表或 profile。选择器过滤 `PROHIBITED`/`UNKNOWN`、
  合规不允许、Provider 不可用、密钥不兼容的候选，并返回有界 `SelectionReport`；随后由 crypto
  服务对选中密钥执行**恰好一次** `PolicyEngine.evaluate`。策略拒绝即终止，不回退。
- **信封**：统一入口为对称 **AEAD/EtM** 与**非对称**算法生成 **v2** 信封。`headerHash` 是版本、
  算法、keyId、已解析的密钥版本、创建时间、salt/KDF 与属性的 SHA-256 绑定。对称算法使用
  “域分隔的 headerHash + 调用方 AAD”作为有效 AAD，篡改会在解密前失败；非对称算法不接收 AAD，
  因此 headerHash 作为前缀封装进密文，解密后、返回明文前校验。非对称算法只能显式选择，自动
  profile 绝不选择它，且非对称请求不允许携带调用方 AAD。统一解密默认拒绝 v1 旧信封，除非请求
  `allowLegacyV1(true)` 且操作员配置也允许；时间窗口检查只接受 v2。
- **密钥版本**：已解析的 `keyVersion` 进入 `headerHash`；即使两个版本材料相同，替换版本也会改变
  受认证的元数据。需要显式钉死时仍可使用 `expectedKeyVersion`。
- **Profile**：`AUTO_AEAD`（默认）、`AUTO_AEAD_THEN_ETM`（显式启用 EtM 块模式）、`FIPS_AEAD`、
  `GM_AEAD`、`GM_HYBRID_AEAD`。自动档位绝不选择非对称算法、实验/弃用算法或更弱模式。
  `selectionCapabilities()` 只列出当前合规模式可用的 profile。
- **密钥**：`keyId`、显式 `candidateKeyIds` 列表，或调用方租户内的显式自动选钥。自动选钥只做
  有界、非策略、非限流的元数据枚举，随后仍由选中密钥执行唯一一次权威策略决策；排序确定
  （最新 ACTIVE 优先）。仅 ACTIVE 密钥默认可保护新数据；DEACTIVATED 密钥可用于历史解密，
  只有在操作员配置 `allow-deactivated-encryption` 与请求标志同时开启时才可加密，策略引擎仍做
  最终决定，且该覆盖会写入审计。候选列表中缺失的密钥会被记录并继续尝试后续密钥；Provider
  故障则终止。
- **能力视图**：`selectionCapabilities()` 列出 installed/compliant/available，不暴露 Provider 类型。
- **配置**：`spissatus.selection.profile`、`preferred-algorithms`、`allow-deprecated`、
  `allow-experimental`、`allow-family-reuse`、`allow-legacy-v1`、`allow-auto-key-selection`、
  `allow-deactivated-encryption`、`max-candidates`。`allow-*` 是操作员上限，请求侧也必须显式
  开启；CLI 标志会同时设置两侧。
- **CLI 迁移**：`spissatus4j decrypt` 现在走统一入口并默认拒绝 v1；使用 `--allow-legacy-v1`
  （同时为该进程打开操作员上限）或重新加密为 v2。`encrypt` 支持 `--auto-key` 与
  `--allow-deactivated-key`。库方法 `decryptEnvelope` 仍兼容 v1。

## Spring Boot Starter（可选）

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
  selection:
    profile: AUTO_AEAD
    allow-auto-key-selection: false
    allow-deactivated-encryption: false
  self-check:
    on-startup: true
    failure-fails-startup: true
  provider:
    jca: true
    bouncycastle: true
    gm: true
    fips: false
```

Starter 注册 `Spissatus` 与 `SpissatusLogSanitizer` Bean；不启动 Web 服务器，也不暴露 HTTP 端点。

## 算法

| 类别 | JCA | Bouncy Castle | GM/T |
| --- | --- | --- | --- |
| AEAD | AES-GCM、ChaCha20-Poly1305 | AES-GCM、ChaCha20-Poly1305 | SM4-GCM |
| 分组（仅 EtM） | AES-CBC/CTR/CFB/OFB | — | SM4-CBC/CTR |
| 非对称 | RSA-OAEP、RSA PKCS#1 v1.5 | RSA-OAEP、ECIES | SM2 |
| 哈希 | SHA-256/384/512、SHA3-256/512 | SHAKE128/256、BLAKE2b | SM3 |
| MAC | HMAC-SHA256/384/512 | HMAC、CMAC-AES | HMAC-SM3 |
| 签名 | Ed25519、Ed448、ECDSA P-256/P-384、RSA-PSS | Ed448、ECDSA、RSA-PSS、RSA PKCS#1 v1.5 | SM2 |
| KDF | PBKDF2、HKDF | Argon2id、scrypt、bcrypt、PBKDF2、HKDF | — |
| 流式 | 分块 AEAD（12 字节 nonce） | — | — |

后量子标识（`ML-KEM-768`、`ML-DSA-65`）与 `Kem`/`HybridKem` 契约已预留，默认拒绝，需显式开启。

## 安全模型

- **每个操作只做一次策略决策**，包括限流与租户检查。
- **Nonce 跟踪**覆盖每次 AEAD/EtM 加密与每个流式 base nonce。
- **Encrypt-then-MAC** 用于 AES-CBC/CTR/CFB/OFB 与 SM4-CBC/CTR，先恒定时间验证再解密。
- **泛化认证失败**，不区分填充、Tag 与密钥错误。
- **密钥状态与用途隔离**：默认仅 ACTIVE 密钥可保护新数据；DEACTIVATED 处理历史数据，只有在
  文档化的操作员与请求双重开关下才可加密。
- **自动选钥从不授权**：枚举是有界、租户内、无策略副作用的；选中密钥仍只执行一次权威策略决策。
- **FIPS 模式**只选择声明 `fipsCapable()` 的 Provider；没有 FIPS Provider 时启动失败。
- **启动自检**校验 Provider；失败即 fail-closed。
- **扩展信任**以模块实现类的完整类名为准，绝不信任自声明的 moduleId。

## 构建与测试

```bash
./gradlew clean build              # 编译、测试、包名检查、jar
./gradlew test                     # 全部模块测试
./gradlew checkPackageNames        # 包名合规检查
```

所有模块必须保持 `cn.tolim.spissatus4j.` 包前缀；`checkPackageNames` 会强制检查。
jar 带 `Automatic-Module-Name` 元数据。

## 参与贡献

提交 Pull Request 前请阅读 [CONTRIBUTING.zh.md](CONTRIBUTING.zh.md)。使用短生命周期分支与 Conventional
Commits，依赖版本统一维护在 [`gradle/libs.versions.toml`](gradle/libs.versions.toml)。

## 安全

请勿在公开 Issue 中披露安全漏洞。请通过 <https://github.com/tolimsuite/spissatus4j> 的私密安全公告，
或私下联系 TOLIM Technologies Pte. Ltd.，并提供复现步骤与受影响版本。禁止提交凭据、私钥或生产数据。

## 许可证

Copyright 2026 TOLIM Technologies Pte. Ltd.

本项目按 [Apache License, Version 2.0](LICENSE) 授权。除非遵守许可证，否则不得使用本项目。
署名信息见 [NOTICE](NOTICE)。
