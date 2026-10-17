#!/bin/bash
# Scope tests for .githooks/pre-push (PREPUSH_PLAN_ONLY=1: plans, no cargo).
# Run: .githooks/test-pre-push.sh  or  just test-hook. The hook runs it when it
# changes. Everything happens in a throwaway clone of this repo with its own
# bare origin; the git environment a hook inherits is cleared first so this can
# never touch the repository it was started from.
set -u
here=$(cd "$(dirname "$0")/.." && pwd)
for v in $(git rev-parse --local-env-vars); do unset "$v"; done
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.invalid
export GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.invalid
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git clone -q --local "$here" "$tmp/r" || exit 1
cd "$tmp/r" || exit 1
[ "$(git rev-parse --show-toplevel)" = "$tmp/r" ] || { echo "not in the scratch clone"; exit 1; }
git init -q --bare "$tmp/o.git"
git remote set-url origin "$tmp/o.git"
git checkout -q -b work
git push -q origin HEAD:refs/heads/main && git fetch -q origin
base=$(git rev-parse HEAD)
ZERO=0000000000000000000000000000000000000000
hook="$here/.githooks/pre-push"
bash=$(command -v bash)

commit() { # commit <file> : append a line, commit, print sha
    mkdir -p "$(dirname "$1")" && echo "// t" >>"$1" && git add "$1" && git commit -qm "t $1" && git rev-parse HEAD
}
out="" rc=0
run() { # run <ref lines...>; env in $ENVV. Sets out, rc.
    # shellcheck disable=SC2086 # ENVV is a list of VAR=value words
    out=$(printf '%s\n' "$@" | env PREPUSH_PLAN_ONLY=1 $ENVV "$bash" "$hook" origin 2>&1)
    rc=$?
}
ENVV=""
fail=0
check() { # check <name> <ok-condition-result>
    if [ "$2" = 0 ]; then echo "ok   $1"; else echo "FAIL $1: rc=$rc out='$out'"; fail=1; fi
}
plan_is() { grep -Eq "^PLAN $1\$" <<<"$out"; check "$2" $?; }
plan_has() { grep -E "^PLAN" <<<"$out" | grep -Eq "$1"; check "$2" $?; }
plan_lacks() { ! grep -E "^PLAN" <<<"$out" | grep -Eq "$1"; check "$2" $?; }
refused() { [ "$rc" != 0 ] && grep -q "$1" <<<"$out" && ! grep -q '^PLAN' <<<"$out"; check "$2" $?; }
at() { git checkout -q --detach "$1"; }

docs=$(commit docs/note.md)
flock=$(commit agent-mesh-flock/src/lib.rs)
data=$(commit agent-mesh-flock/src/data.bin)
lock=$(commit Cargo.lock)
leaf=$(commit agent-mesh-transport-ssh/src/lib.rs)

at "$leaf"
run "refs/heads/w $docs refs/heads/w $base"
plan_is skip "docs-only push skips (even when not HEAD)"
run "(delete) $ZERO refs/heads/w $docs"
plan_is skip "branch deletion skips"
run "refs/tags/v1 $leaf refs/tags/v1 $ZERO"
plan_is skip "tag push skips"

at "$flock"
run "refs/heads/w $flock refs/heads/w $docs"
plan_has 'agent-mesh-flock .*agent-mesh-flock-server' "flock change -> flock + rdeps"
plan_has 'agent-mesh-cli' "rdeps include the cli"
plan_lacks 'agent-mesh-protocol|transport-ssh' "...and not unrelated crates"
run "refs/heads/new $flock refs/heads/new $ZERO"
plan_has 'agent-mesh-flock' "new branch measured from origin/main"

at "$data"
run "refs/heads/w $data refs/heads/w $flock"
plan_has 'agent-mesh-flock' "a fixture-only change (include_bytes) selects its crate"

at "$lock"
run "refs/heads/w $lock refs/heads/w $data"
plan_is full "Cargo.lock -> whole tree"

at "$leaf"
run "refs/heads/w $leaf refs/heads/w $lock"
plan_is 'crates: agent-mesh-transport-ssh' "leaf crate -> only itself"

run "refs/heads/w $leaf refs/heads/w deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
plan_is full "unknown remote sha -> whole tree, never a skip"

git remote set-url origin /nonexistent
git update-ref -d refs/remotes/origin/main
run "refs/heads/new $leaf refs/heads/new $ZERO"
plan_is full "no merge-base for a new branch -> whole tree"
git remote set-url origin "$tmp/o.git" && git fetch -q origin

mkdir "$tmp/fake"
real=$(command -v cargo)
# shellcheck disable=SC2016 # the script body expands later
printf '#!/bin/sh\n[ "$1" = metadata ] && exit 37\nexec "%s" "$@"\n' "$real" >"$tmp/fake/cargo"
chmod +x "$tmp/fake/cargo"
ENVV="PATH=$tmp/fake:$PATH"
run "refs/heads/w $leaf refs/heads/w $lock"
plan_is full "cargo metadata failing -> whole tree"

mkdir "$tmp/nojq"
for t in git cargo grep sort; do ln -s "$(command -v $t)" "$tmp/nojq/$t"; done
ENVV="PATH=$tmp/nojq"
run "refs/heads/w $leaf refs/heads/w $lock"
plan_is full "jq missing -> whole tree"
grep -q "'jq' not found" <<<"$out"
check "jq missing is explained" $?
ENVV=""

at "$leaf"
run "refs/heads/w $flock refs/heads/w $docs"
refused "not the checked-out commit" "a non-HEAD code tip is refused"

echo x >untracked.txt
run "refs/heads/w $leaf refs/heads/w $lock"
refused "modified or untracked" "an untracked file is refused"
rm untracked.txt

run "refs/heads/a $flock refs/heads/a $docs" "refs/heads/b $leaf refs/heads/b $lock"
refused "one branch at a time" "two code tips are refused"

run "refs/tags/v1 $leaf refs/tags/v1 $ZERO" "(delete) $ZERO refs/heads/x $docs" "refs/heads/w $leaf refs/heads/w $lock"
plan_is 'crates: agent-mesh-transport-ssh' "tag + deletion + branch: only the branch counts"
exit $fail
