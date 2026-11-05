#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
UPSTREAM=$TMP/upstream
CACHE=$TMP/cache
mkdir -p "$UPSTREAM"

cat > "$UPSTREAM/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.20)
project(ProxyNightmareFixture LANGUAGES CXX)
enable_testing()
add_executable(pn pn.cpp)
add_executable(pn_tests tests.cpp)
add_test(NAME pn_tests COMMAND pn_tests)
EOF
cat > "$UPSTREAM/pn.cpp" <<'EOF'
int main() { return 0; }
EOF
cat > "$UPSTREAM/tests.cpp" <<'EOF'
int main() { return 0; }
EOF

git -C "$UPSTREAM" init -q -b main
git -C "$UPSTREAM" -c user.name=fixture -c user.email=fixture@example.invalid \
    add CMakeLists.txt pn.cpp tests.cpp
git -C "$UPSTREAM" -c user.name=fixture -c user.email=fixture@example.invalid \
    commit -qm initial
COMMIT=$(git -C "$UPSTREAM" rev-parse HEAD)
cat > "$TMP/proxy-nightmare.lock" <<EOF
PROXY_NIGHTMARE_REPOSITORY=file://$UPSTREAM
PROXY_NIGHTMARE_COMMIT=$COMMIT
EOF

"$HERE/prepare-proxy-nightmare.sh" "$CACHE" "$TMP/proxy-nightmare.lock" 2 \
    > "$TMP/first.log"
[[ -x $CACHE/build/pn ]]
[[ $(git -C "$CACHE" rev-parse HEAD) == "$COMMIT" ]]
[[ $(<"$CACHE/build/.smithproxy-tested-commit") == "$COMMIT" ]]
grep -q '100% tests passed' "$TMP/first.log"

FIRST_MTIME=$(stat -c %y "$CACHE/build/pn")
"$HERE/prepare-proxy-nightmare.sh" "$CACHE" "$TMP/proxy-nightmare.lock" 2 \
    > "$TMP/second.log"
[[ $(stat -c %y "$CACHE/build/pn") == "$FIRST_MTIME" ]]
! grep -q 'Test project' "$TMP/second.log"

echo 'PASS: ProxyNightmare acquisition is pinned, tested and cached'
