#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/root"
: > "$TMP/root/CMakeLists.txt"

cat > "$TMP/bin/cmake" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat > "$TMP/bin/ctest" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$@" > "$CTEST_ARGUMENTS"
echo '100% tests passed, 0 tests failed out of 1'
EOF
chmod +x "$TMP/bin/cmake" "$TMP/bin/ctest"

CTEST_ARGUMENTS="$TMP/ctest.args" PATH="$TMP/bin:$PATH" \
    "$HERE/native-tests.sh" --root "$TMP/root" --build-dir "$TMP/build" \
    --report-dir "$TMP/report" --jobs 17 --test-jobs 3 >/dev/null

grep -Fx -- '-j3' "$TMP/ctest.args" >/dev/null || {
    echo 'native-tests.sh did not propagate --test-jobs 3 to CTest' >&2
    exit 1
}
if grep -Fx -- '-j17' "$TMP/ctest.args" >/dev/null; then
    echo 'build parallelism leaked into CTest concurrency' >&2
    exit 1
fi

echo 'PASS: native CTest concurrency follows the explicit correctness-gate limit'
