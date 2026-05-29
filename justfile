# agent-mesh — task runner
#
# PIPELINE PARITY: This justfile is the local mirror of the CI pipeline
# at .github/workflows/ci.yml and the pre-push hook at .githooks/pre-push.
# When editing any of the three, audit the others in the same PR.
#
# Quick reference:
#   just                — list available recipes (default)
#   just check          — full local gate (fmt + clippy + test)
#   just cov            — local coverage with HTML report
#   just cov-ci         — coverage with 75% gate, lcov output (CI mode)
#   just install-hooks  — wire .githooks/ as the repo's hooks path

default:
    @just --list

# --- Build ---

# Default debug build for the whole workspace.
build:
    cargo build --workspace

# Optimized release build for the whole workspace.
release:
    cargo build --workspace --release

# --- Test ---

# Run every test in the workspace.
test:
    cargo test --workspace

# --- Lint & format ---

# Apply rustfmt to the whole workspace.
fmt:
    cargo fmt --all

# Lint with zero-warnings gate.
lint:
    cargo clippy --workspace --all-targets -- -D warnings

# fmt-check, lint, and test — the local equivalent of CI.
# PIPELINE PARITY: must match .github/workflows/ci.yml.
check:
    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets -- -D warnings
    cargo test --workspace

# --- Coverage ---

# Generate an HTML coverage report for human review.
cov:
    cargo llvm-cov --workspace --html
    @echo "HTML report at target/llvm-cov/html/index.html"

# CI-mode coverage: emit lcov + enforce the current floor.
# PIPELINE PARITY: must match the coverage job in .github/workflows/ci.yml.
#
# Floor: 75% workspace-wide. Ratchet UP only, never down. Each PR that
# adds tests should bump this threshold higher; each PR that adds
# untested code will fail the gate.
cov-ci:
    cargo llvm-cov --workspace --lcov --output-path lcov.info --fail-under-lines 75

# --- Hook installation ---

# Point this repo at .githooks/ for pre-push gating.
# Idempotent — safe to re-run.
install-hooks:
    git config core.hooksPath .githooks
    @echo "core.hooksPath -> .githooks"
