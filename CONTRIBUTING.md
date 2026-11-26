# Contributing to spissatus4j

Thank you for contributing. spissatus4j is a cryptographic engineering library: correctness, security and
predictable failure behaviour matter more than feature volume.

## Before you start

- Read this file and the relevant module README/tests before changing code.
- Open an issue for non-trivial changes and agree on the scope first.
- Search for an existing implementation before adding a new abstraction.
- Never add mock, fake, demo, seed or sample data to production sources or tests that pretend to test real
  behaviour. Use real APIs and deterministic fixtures.

## Branching

- `main` is the only long-lived branch and the release branch.
- Branch from the latest `origin/main` using `<type>/<name>`, for example `feat/stream-resume` or
  `fix/key-tombstone`.
- One branch, one task. Rebase on `origin/main` before opening a pull request.
- Do not push directly to `main` or rewrite shared history.

## Commits

- Use single-line Conventional Commits: `<type>: <subject>`.
- Keep the subject lowercase, imperative and under 72 characters, without a trailing period.
- One logical change per commit.
- Add tests for behaviour changes. Never disable a test to make a change pass.

Examples:

```text
feat: add chunked aead resume support
fix: reject frame length sentinel collision
docs: publish readme and apache license
```

## Code rules

- Java 25, Gradle Wrapper 9.9. Do not add a second build tool.
- Dependency versions live in `gradle/libs.versions.toml`; explain any new dependency in the pull request.
- Keep the dependency direction: `contract` is dependency-free; `core` depends on `contract`; implementation
  modules depend on `contract`/`core`; `starter` aggregates implementation modules.
- Never use `java.util.Random`, `Math.random` or a non-CSPRNG for keys, nonces, salts or tokens.
- Never log or throw secrets, plaintext, passwords, private keys or complete ciphertext.
- Tag/MAC comparisons must be constant-time; authentication failures must use generic messages.
- New non-AEAD modes must be wrapped with Encrypt-then-MAC; do not expose raw block modes.
- Keep `internal` packages internal: they are not part of the compatibility surface.
- All Java packages must start with `cn.tolim.spissatus4j.`.

## Tests and checks

Run before opening a pull request:

```bash
./gradlew test
./gradlew checkPackageNames
./gradlew clean build
```

Add or update tests for every behaviour change. Known-answer vectors (NIST, RFC, GM/T) are strongly preferred
for algorithm code. Security fixes must include a regression test that fails on the previous implementation.

## Releasing

The release version lives in `settings.gradle`:

```groovy
gradle.ext.spissatusVersion = '0.1.0'
```

To release, update that value, update `CHANGELOG.md`/`CHANGELOG.zh.md`, and merge to `main`. The
`Release` GitHub workflow detects the version change on `settings.gradle`, builds and tests, signs all
publications, uploads the complete Maven repository bundle to Maven Central, waits for Central validation,
and only then creates the `v<version>` GitHub release and tag. Re-running the workflow does nothing when the
tag already exists.

Required repository secrets:

| Secret | Purpose |
| --- | --- |
| `MAVEN_CENTRAL_USERNAME` | Central Portal user-token username |
| `MAVEN_CENTRAL_PASSWORD` | Central Portal user-token password |
| `SIGNING_KEY` | ASCII-armored PGP private key used by the Gradle signing plugin |
| `SIGNING_PASSWORD` | PGP key passphrase |

The `cn.tolim.spissatus4j` namespace must be verified in the Central Portal before the first publication.
`workflow_dispatch` can be used to retry an unpublished version manually.

## Pull requests

- Keep pull requests small and focused on one problem.
- Describe what changed, affected modules, verification performed, and any migration or manual step.
- PR titles and descriptions are in English.
- A pull request is merged only after review and all comments are addressed; use rebase and merge to keep
  `main` linear.

## License

By submitting a contribution you agree that it is licensed under the repository's
[Apache License 2.0](LICENSE), and you confirm that you have the right to submit it under that license.

Copyright 2026 TOLIM Technologies Pte. Ltd.
