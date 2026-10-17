#!/bin/bash
# Scope tests for .githooks/pre-push (PREPUSH_PLAN_ONLY=1: plans, no cargo).
# Run: .githooks/test-pre-push.sh   (HOOK PARITY: not part of CI's cargo jobs;
# `just test-hook` runs it, and the pre-push hook does when .githooks changes.)
set -u
here=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git clone -q --local "$here" "$tmp/r" || exit 1
cd "$tmp/r" || exit 1
git config user.email t@example.invalid
git config user.name t
git checkout -q -b work
base=$(git rev-parse HEAD)
git update-ref refs/remotes/origin/main "$base"
ZERO=0000000000000000000000000000000000000000

commit() { # commit <file> : append a line, commit, print sha
    mkdir -p "$(dirname "$1")" && echo "// t" >>"$1" && git add "$1" && git commit -qm "t $1" && git rev-parse HEAD
}
plan() { # plan <lref> <lsha> <rref> <rsha>
    echo "$*" | PREPUSH_PLAN_ONLY=1 bash "$here/.githooks/pre-push" 2>&1 | sed -n 's/^PLAN //p'
}
fail=0
expect() { # expect <name> <got> <want-regex> [<not-regex>]
    if ! grep -Eq "$3" <<<"$2" || { [ -n "${4:-}" ] && grep -Eq "$4" <<<"$2"; }; then
        echo "FAIL $1: got '$2'"
        fail=1
    else
        echo "ok   $1"
    fi
}

docs=$(commit docs/note.md)
expect "docs-only push skips" "$(plan refs/heads/work "$docs" refs/heads/work "$base")" '^skip$'
expect "branch deletion skips" "$(plan "(delete)" $ZERO refs/heads/work "$docs")" '^skip$'
expect "tag push skips" "$(plan refs/tags/v1 "$docs" refs/tags/v1 $ZERO)" '^skip$'

flock=$(commit agent-mesh-flock/src/lib.rs)
got=$(plan refs/heads/work "$flock" refs/heads/work "$docs")
expect "flock change -> flock + rdeps" "$got" 'agent-mesh-flock .*agent-mesh-flock-server' 'agent-mesh-protocol|transport-ssh'
expect "rdeps include the cli" "$got" 'agent-mesh-cli'

got=$(plan refs/heads/work "$flock" refs/heads/new $ZERO)
expect "new branch measured from origin/main" "$got" 'agent-mesh-flock'
cargo=$(commit Cargo.lock)
expect "Cargo.lock -> whole workspace" "$(plan refs/heads/work "$cargo" refs/heads/work "$flock")" '^workspace$'
leaf=$(commit agent-mesh-transport-ssh/src/lib.rs)
expect "leaf crate -> only itself" "$(plan refs/heads/work "$leaf" refs/heads/work "$cargo")" '^crates: agent-mesh-transport-ssh$'
exit $fail
