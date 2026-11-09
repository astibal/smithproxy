#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 ROOT LOCK_FILE JOBS" >&2
    exit 2
}

[[ $# == 3 ]] || usage
ROOT=$1
LOCK_FILE=$2
JOBS=$3
[[ $ROOT == /* && $LOCK_FILE == /* ]] || {
    echo 'ProxyNightmare root and lock file must be absolute paths' >&2
    exit 2
}
[[ $JOBS =~ ^[1-9][0-9]*$ ]] || { echo 'jobs must be positive' >&2; exit 2; }
[[ -f $LOCK_FILE ]] || { echo "missing ProxyNightmare lock: $LOCK_FILE" >&2; exit 2; }

# The lock is repository-owned trusted shell containing two scalar assignments.
# shellcheck source=/dev/null
source "$LOCK_FILE"
: "${PROXY_NIGHTMARE_REPOSITORY:?missing repository in lock}"
: "${PROXY_NIGHTMARE_COMMIT:?missing commit in lock}"
[[ $PROXY_NIGHTMARE_COMMIT =~ ^[0-9a-f]{40}$ ]] || {
    echo 'ProxyNightmare lock must contain a full 40-character commit SHA' >&2
    exit 2
}

for command in git cmake ctest flock; do
    command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 2; }
done

mkdir -p "$(dirname "$ROOT")"
exec 9>"$ROOT.prepare.lock"
flock 9

if [[ ! -d $ROOT/.git ]]; then
    [[ ! -e $ROOT ]] || { echo "non-Git path blocks ProxyNightmare cache: $ROOT" >&2; exit 2; }
    git clone --filter=blob:none --no-checkout "$PROXY_NIGHTMARE_REPOSITORY" "$ROOT"
else
    actual_repository=$(git -C "$ROOT" remote get-url origin)
    [[ $actual_repository == "$PROXY_NIGHTMARE_REPOSITORY" ]] || {
        echo "ProxyNightmare cache has unexpected origin: $actual_repository" >&2
        exit 2
    }
fi

if ! git -C "$ROOT" cat-file -e "$PROXY_NIGHTMARE_COMMIT^{commit}" 2>/dev/null; then
    git -C "$ROOT" fetch --depth 1 origin "$PROXY_NIGHTMARE_COMMIT"
fi
git -C "$ROOT" checkout --detach --force "$PROXY_NIGHTMARE_COMMIT"
[[ $(git -C "$ROOT" rev-parse HEAD) == "$PROXY_NIGHTMARE_COMMIT" ]]

STAMP=$ROOT/build/.smithproxy-tested-commit
if [[ ! -x $ROOT/build/pn || ! -f $STAMP || $(<"$STAMP") != "$PROXY_NIGHTMARE_COMMIT" ]]; then
    cmake -S "$ROOT" -B "$ROOT/build" -DCMAKE_BUILD_TYPE=Release
    cmake --build "$ROOT/build" --target pn pn_tests -j"$JOBS"
    # Gate the staged tool on its deterministic parser/runtime unit tests.
    # Smithproxy's lifecycle profile exercises the network scenarios itself;
    # upstream loopback integration tests are timing-sensitive and would make
    # dependency preparation an unrelated source of full-run failures.
    ctest --test-dir "$ROOT/build" --output-on-failure -R '^pn_tests$'
    printf '%s\n' "$PROXY_NIGHTMARE_COMMIT" > "$STAMP"
fi

[[ -x $ROOT/build/pn ]] || { echo 'ProxyNightmare build did not produce pn' >&2; exit 1; }
echo "ProxyNightmare ready: $PROXY_NIGHTMARE_COMMIT ($ROOT/build/pn)"
