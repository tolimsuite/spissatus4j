# 参与贡献 spissatus4j

感谢你为 spissatus4j 贡献代码。这是一个密码学工程封装库：正确性、安全性与可预测的失败行为比功能数量更重要。

## 开始之前

- 修改代码前先阅读本文件及相关模块的测试与文档。
- 非简单改动请先开 Issue，确认方案与范围。
- 创建新的抽象前先搜索仓库中是否已有实现，优先复用或扩展。
- 禁止在仓库任何位置添加 mock、fake、demo、种子或桩数据；测试必须使用真实 API 与确定性 fixture。

## 分支

- `main` 是唯一的长期分支与发布分支。
- 从最新的 `origin/main` 创建短生命周期分支：`<type>/<name>`，例如 `feat/stream-resume` 或
  `fix/key-tombstone`。
- 一个分支只负责一个任务；提交 Pull Request 前先 rebase 到 `origin/main`。
- 禁止直接推送 `main`，禁止改写共享历史。

## 提交

- 使用单行 Conventional Commits：`<type>: <subject>`。
- subject 使用小写英文、祈使语气，不超过 72 个字符，结尾不加句号。
- 一个提交只做一件事。
- 行为变更必须同时新增或更新测试。禁止为了让改动通过而禁用测试。

示例：

```text
feat: add chunked aead resume support
fix: reject frame length sentinel collision
docs: publish readme and apache license
```

## 代码规范

- 使用 Java 25 与 Gradle Wrapper 9.9；禁止引入第二套构建工具。
- 依赖版本统一维护在 `gradle/libs.versions.toml`；Pull Request 必须说明新增依赖的用途。
- 保持依赖方向：`contract` 无第三方依赖；`core` 依赖 `contract`；实现模块依赖 `contract`/`core`；
  `starter` 聚合实现模块。
- 生成密钥、Nonce、盐或令牌时禁止使用 `java.util.Random`、`Math.random` 或非 CSPRNG。
- 禁止在日志或异常中输出密钥、明文、口令、私钥或完整密文。
- Tag/MAC 比较必须恒定时间；认证失败必须使用泛化消息。
- 新的非 AEAD 模式必须使用 Encrypt-then-MAC；不得暴露裸分组模式。
- `internal` 包不属于兼容性表面，不得在公开 API 中泄漏。
- 所有 Java 包名必须以 `cn.tolim.spissatus4j.` 开头。

## 测试与检查

提交 Pull Request 前运行：

```bash
./gradlew test
./gradlew checkPackageNames
./gradlew clean build
```

任何行为变更都必须补测试。算法代码优先使用 NIST、RFC、GM/T 已知答案向量。安全修复必须包含一个在旧实现上
会失败的回归测试。

## 发布

发布版本号统一维护在 `settings.gradle`：

```groovy
gradle.ext.spissatusVersion = '0.1.0'
```

要发布新版本，修改该值，同时更新 `CHANGELOG.md` / `CHANGELOG.zh.md`，然后合并到 `main`。`Release`
GitHub 工作流会检测 `settings.gradle` 的版本变化，执行构建与测试、签名全部制品、把完整 Maven 仓库
bundle 上传到 Maven Central，等待 Central 校验完成后再创建 `v<version>` GitHub Release 与 tag。
如果 tag 已存在，重复运行不会重复发布。

需要配置的仓库 Secret：

| Secret | 用途 |
| --- | --- |
| `MAVEN_CENTRAL_USERNAME` | Central Portal 用户令牌用户名 |
| `MAVEN_CENTRAL_PASSWORD` | Central Portal 用户令牌密码 |
| `SIGNING_KEY` | Gradle signing 使用的 ASCII-armored PGP 私钥 |
| `SIGNING_PASSWORD` | PGP 私钥口令 |

首次发布前需要在 Central Portal 验证 `cn.tolim.spissatus4j` 命名空间。可用 `workflow_dispatch` 手动重试
尚未发布的版本。

## Pull Request

- Pull Request 保持小而聚焦，一个 PR 解决一个问题。
- 说明改了什么、影响哪些模块、如何验证，以及是否存在迁移或人工步骤。
- 标题与描述使用英文。
- 只有评审通过且所有意见处理完毕才能合并；使用 rebase and merge 保持 `main` 线性。

## 许可证

提交贡献即表示你同意该贡献按仓库的 [Apache License 2.0](LICENSE) 授权，并确认你有权以该许可证提交它。

Copyright 2026 TOLIM Technologies Pte. Ltd.
