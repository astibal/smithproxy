#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/pn/build"
touch "$TMP/pn/build/pn"
chmod +x "$TMP/pn/build/pn"

cat > "$TMP/bin/sudo" <<'EOF'
#!/usr/bin/env bash
echo "unexpected local sudo: $*" >> "$PREFLIGHT_TEST_LOG"
exit 91
EOF

cat > "$TMP/bin/ssh" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' '--- ssh invocation ---' "$@" >> "$PREFLIGHT_TEST_LOG"
command=${*: -1}
if [[ $command == *'sudo -n true'* ]]; then
    echo sudo-n
    exit 0
fi
if [[ $command == 'sudo -n bash -s -- privileged' ]]; then
    if [[ ${PREFLIGHT_TEST_PRIVILEGED_RESULT:-fail} == pass ]]; then
        exit 0
    fi
    echo 'simulated remote privilege probe failure' >&2
    exit 77
fi
if [[ $command == 'bash -s -- rootless' ]]; then
    exit 0
fi
exit 78
EOF
chmod +x "$TMP/bin/sudo" "$TMP/bin/ssh"

export PREFLIGHT_TEST_LOG=$TMP/calls.log
export PATH=$TMP/bin:$PATH

# A build-only profile must not touch sudo or SSH.
"$HERE/test-patch.sh" quick --local --preflight-only > "$TMP/quick.out"
grep -q 'backend=unprivileged result=PASS' "$TMP/quick.out"
[[ ! -e $PREFLIGHT_TEST_LOG ]]

# A remote privileged target must use batch SSH, bounded connection setup and
# sudo -n. The simulated capability failure must propagate immediately.
if "$HERE/test-patch.sh" sanity --remote test.invalid --preflight-only \
        > "$TMP/privileged.out" 2>&1; then
    echo 'privileged preflight unexpectedly passed' >&2
    exit 1
fi
grep -q 'backend=sudo-n result=FAIL' "$TMP/privileged.out"
grep -qx 'BatchMode=yes' "$PREFLIGHT_TEST_LOG"
grep -qx 'ConnectTimeout=10' "$PREFLIGHT_TEST_LOG"
grep -qx 'sudo -n bash -s -- privileged' "$PREFLIGHT_TEST_LOG"

# Lifecycle must use the rootless backend and never ask for sudo.
: > "$PREFLIGHT_TEST_LOG"
"$HERE/test-patch.sh" lifecycle --remote test.invalid --preflight-only \
    --proxy-nightmare-root "$TMP/pn" > "$TMP/rootless.out"
grep -q 'backend=rootless mode=rootless result=PASS' "$TMP/rootless.out"
grep -qx 'bash -s -- rootless' "$PREFLIGHT_TEST_LOG"
if grep -q 'sudo' "$PREFLIGHT_TEST_LOG"; then
    echo 'rootless lifecycle unexpectedly used sudo' >&2
    exit 1
fi

# Hosted CI can explicitly select the privileged lifecycle backend while the
# default remains rootless for developers and ordinary remote targets.
: > "$PREFLIGHT_TEST_LOG"
PREFLIGHT_TEST_PRIVILEGED_RESULT=pass PATCH_TEST_LIFECYCLE_PRIVILEGED=1 \
    "$HERE/test-patch.sh" lifecycle --remote test.invalid --preflight-only \
    --proxy-nightmare-root "$TMP/pn" > "$TMP/privileged-lifecycle.out"
grep -q 'backend=sudo-n mode=privileged result=PASS' "$TMP/privileged-lifecycle.out"
grep -qx 'sudo -n bash -s -- privileged' "$PREFLIGHT_TEST_LOG"
if grep -qx 'bash -s -- rootless' "$PREFLIGHT_TEST_LOG"; then
    echo 'privileged lifecycle unexpectedly used the rootless probe' >&2
    exit 1
fi

echo 'PASS: privilege preflight is early, non-interactive and profile-aware'
