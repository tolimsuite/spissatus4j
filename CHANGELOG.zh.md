# 变更日志

spissatus4j 的重要变更记录在此。

## [Unreleased]

### 新增

- 统一 `Spissatus.encrypt(UnifiedEncryptRequest)` / `decrypt(UnifiedDecryptRequest)` 入口：
  从已安装、合规、已授权且与密钥兼容的能力中确定性选择唯一主算法；支持有序候选、命名套件与
  `AUTO_AEAD` / `AUTO_AEAD_THEN_ETM` / FIPS / GM profile。
- 信封 v2：`headerHash` 以 SHA-256 绑定版本、算法、keyId、已解析的密钥版本、创建时间、
  salt/KDF 与属性；有效 AAD 域分隔，解密时重建。对称 AEAD/EtM 将 headerHash 作为 AAD 认证；
  非对称算法不接收 AAD，因此将其作为密文前缀并在返回明文前校验。
- 租户内显式自动选钥（`allow-auto-key-selection` + `autoKeySelection`）：有界、非策略的描述符
  枚举与确定性排序；选中密钥仍只执行一次权威策略决策。
- DEACTIVATED 密钥加密双重开关（`allow-deactivated-encryption` + 请求标志）；默认 usage 策略
  认可该标志，且每次覆盖都会写入 `KEY_STATE_OVERRIDE` 审计事件。
- `PolicyEngine` 选择 hints（非权威、不产生限流副作用）；选择报告、能力视图、审计事件与有界指标。
- Spring Boot `spissatus.selection.*` 配置（含自动选钥与 DEACTIVATED 加密上限）；CLI 统一
  加密/解密支持 `--keys`、`--suite`、`--profile`、`--auto-key`、`--allow-deactivated-key`
  与 `--allow-legacy-v1`。
- 默认密钥管理器支持 ChaCha20-Poly1305 密钥生成。

### 安全

- 对称 AEAD/EtM 的 v2 信封元数据被篡改时在解密前发现；非对称信封在解密后、返回明文前发现。
  v1 旧信封需要请求标志与操作员上限同时允许。CLI 解密 v1 需要 `--allow-legacy-v1`。
- `keyVersion` 进入 v2 `headerHash`；即使两个版本材料相同，替换版本也会改变受认证元数据。
  `expectedKeyVersion` 仍可作为显式钉死。
- 操作员 `spissatus.selection.allow-*` 是硬上限；请求标志不能开启被操作员关闭的能力（包括
  低层 `EncryptRequest` 调用）。CLI 标志会同时设置两侧。
- 自动选钥枚举绝不调用策略引擎、不触发轮换、不消耗限流令牌，也不返回其他租户的密钥。
- 统一解密将 tag、padding 与密文失败统一泛化为认证失败。
- 每次统一操作仅一次权威策略决策；策略拒绝不切换到其他算法或密钥。
- FIPS/GM 路由按合规模式与 Provider 能力过滤；`Capabilities.fipsAvailable` 改为反映已安装的
  FIPS-capable Provider。
- v2 头部域在发布前已最终确定（现包含密钥版本与非对称绑定）；由未发布的旧构建生成的 v2 信封
  需要重新加密。
- 流式指标使用有界算法标签（未注册为 `unknown`）。

## [0.1.0] - 2026-11-26

首次公开发布。

### 新增

- 契约优先的门面、值对象、密封异常体系、SPI 与合规模块。
- fail-closed 核心运行时：构建器、启动自检、恒定时间比较、脱敏、Nonce 复用检测、扩展注册与模块信任。
- JCA Provider：AES-GCM、ChaCha20-Poly1305、AES-CBC/CTR/CFB/OFB（Encrypt-then-MAC）、RSA-OAEP、
  RSA PKCS#1 v1.5、Ed25519、Ed448、ECDSA、RSA-PSS、SHA-2/SHA-3、HMAC、PBKDF2、HKDF 与分块 AEAD 流。
- 密钥生命周期：状态机、用途与租户隔离、轮换、版本保留、包装、导入导出、memory/file/environment/
  keystore Provider 与销毁。
- 自描述 TLV/JSON 信封，严格解析、版本策略与文本编码。
- 策略引擎：算法、用途、访问、租户与合规规则，最严格优先合并与 fail-closed 限流。
- Bouncy Castle Provider：FIPS 路由、Argon2id、scrypt、bcrypt、SHAKE、BLAKE2b、ECIES、CMAC-AES 与
  RSA PKCS#1 v1.5 签名。
- 国密 Provider：SM2 加解密/签名/包装、SM3、HMAC-SM3、SM4-GCM/CBC/CTR，含官方测试向量。
- 可选 Spring Boot 4 Starter：自动配置、属性、日志脱敏与 CLI。
- Apache License 2.0、README/README.zh、CONTRIBUTING/CONTRIBUTING.zh 与版本目录。

### 安全

- 默认拒绝 ECB、DES、RC4、MD5、SHA-1 与实验性算法。
- 认证失败泛化；所有 Encrypt-then-MAC 模式先验证后解密。
- Nonce 复用检测、FIPS Provider 门禁与精确类名模块信任。
