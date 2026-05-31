# agent-mesh — rules for agents

This file is the per-project rule sheet. Read it before opening any PR
into this repository. The user-facing CLI (`amesh`) is the deliverable
for end-users; everything here is plumbing to make that CLI honest.

## Identity & attribution

- Author email on every commit: `hartsock@users.noreply.github.com`.
- Append a `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`
  trailer when an agent is at the keyboard.

## Versioning

This workspace uses **semver** (`0.MINOR.PATCH`). The first crates.io
release is **`0.1.0`**; the earlier pre-publish date-based scheme
(`0.{month}.{YYYYMMDD}`) is retired. All workspace members share one
version via `workspace.package.version` and publish in lock-step — bump
it in the release PR.

## Build & test gates

Every PR must clear the same bar locally that CI enforces:

```sh
just install-hooks   # one-time per clone
just check           # fmt + clippy (-D warnings) + cargo test
just cov-ci          # cargo llvm-cov --fail-under-lines 75
```

Coverage floor is **75% workspace-wide**, ratcheted up over time.
Never lower it; if a PR drops coverage, add tests until it clears.

`just check && just cov-ci` is what the pre-push hook runs. Do NOT
bypass the hook with `--no-verify`. If a check fails, fix the
underlying issue.

## PR shape

- **One step per PR.** Multi-purpose PRs are hard to review and hard
  to roll back. A "step" is one logical change with its own tests.
- PR body has three sections — keep this exact shape:

  ```markdown
  ## What this PR does

  - bullet
  - bullet
  - bullet

  ## Test plan

  - what was tested, and how
  - links to test files and approximate counts

  ## Out of scope

  - explicit non-goals; what's deferred to which later phase
  ```

- Branch lifetime: hours to days, not weeks. Close branches early.
- Real PRs only — agents MUST NOT push to `main`.

## Hook & pipeline parity

`.githooks/pre-push`, `justfile`, and `.github/workflows/ci.yml` are
mirrors of each other. When you edit any one of them, audit the
other two in the same PR. Each file carries a `PIPELINE PARITY` or
`HOOK PARITY` comment pointing at its counterparts; keep them current.

## Coding rules

- **Zero clippy warnings.** `cargo clippy --workspace --all-targets -- -D warnings`
  must be clean.
- **`cargo fmt --all`** before every commit.
- **No `Date::now()` / `SystemTime::now()` in core crates.** Wall-clock
  time is not a coordination primitive; accept timestamps as parameters
  where they're load-bearing. Tests use fixed RFC 3339 strings.
- **Never commit private keys, signatures, or secrets.** The `.gitignore`
  blocks `*.key` and `*.sig`; don't fight it.
- **No secrets in code or tests.** Test SSH keys are generated
  in-memory in the test body, not shipped as fixtures.
