#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REAL_CTEST=$(command -v ctest)
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

# Exercise the actual CTest exit status: an empty selection is not a passing
# correctness gate, and a failing test must survive the logging pipeline.
rm "$TMP/bin/ctest"
ln -s "$REAL_CTEST" "$TMP/bin/ctest"
check_failure() {
    local name=$1
    local rc=0
    PATH="$TMP/bin:$PATH" "$HERE/native-tests.sh" \
        --root "$TMP/root" --build-dir "$TMP/build" \
        --report-dir "$TMP/$name" --jobs 1 >"$TMP/$name.log" 2>&1 || rc=$?
    if ((rc == 0)) || grep -q '^PASS:' "$TMP/$name.log"; then
        cat "$TMP/$name.log" >&2
        echo "native gate incorrectly passed: $name" >&2
        exit 1
    fi
}

check_failure empty
grep -q 'No tests were found' "$TMP/empty/ctest.log"

cat > "$TMP/build/CTestTestfile.cmake" <<'EOF'
add_test(failing "/bin/false")
EOF
check_failure failing
grep -q 'failing' "$TMP/failing/ctest.log"

cat > "$TMP/build/CTestTestfile.cmake" <<'EOF'
add_test(excluded "/bin/true")
set_tests_properties(excluded PROPERTIES LABELS "external")
EOF
check_failure excluded
grep -q 'No tests were found' "$TMP/excluded/ctest.log"

echo 'PASS: native gate rejects empty, fully excluded and failing test runs'
