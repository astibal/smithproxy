# Testing cheatsheet

Run commands from the repository root. A target is always mandatory:
`--local` or `--remote [USER@]HOST`.

```bash
# Fast compile check
tests/patch-runner/test-patch.sh quick --local

# C++, Python, QUIC and runner self-tests
tests/patch-runner/test-patch.sh native --local

# Short dual-stack functional check
tests/patch-runner/test-patch.sh sanity --remote root@test-runner

# Normal comprehensive gate (recommended concurrency)
tests/patch-runner/test-patch.sh full --remote root@test-runner --parallel 3

# Combined native + local dataplane line coverage (requires sudo/root)
tests/patch-runner/test-patch.sh coverage --local --jobs 8

# Deterministic fuzz regression layer / new exploratory seed
tests/patch-runner/test-patch.sh fuzz --remote root@test-runner --parallel 3
tests/patch-runner/test-patch.sh fuzz-dyn --remote root@test-runner --parallel 3

# One focused area
tests/patch-runner/test-patch.sh sanity --suite tls --remote root@test-runner
tests/patch-runner/test-patch.sh fuzz --suite fuzz.h2 --seed SEED --local

# Compile in detailed proxy/epoll trace logging for a diagnostic run
PATCH_TEST_BUILD_TYPE=Debug tests/patch-runner/test-patch.sh sanity --suite transfer \
  --env TLS_EVASION_TRACE=1 --remote root@test-runner
```

Useful additions:

```text
--unique=NAME       do not collide with another run
--dir /tmp/NAME     predictable work and report path
--quiet             verdicts and report path only
--parallel N        concurrent isolated sections per target
--include-external  public-network and privileged native tests
--include-extended  long QUIC soak tests
--include-platform  Docker distribution matrix
PATCH_TEST_CTEST_JOBS=N  deliberately parallelize gcov test executables
PATCH_TEST_BUILD_TYPE=Debug build with detailed trace logging retained
```

Find results:

```bash
cat  /tmp/patch-runner/*/results/*/summary.txt
tail -f /tmp/patch-runner/*/results/*/test.log
```

For semantics, pass criteria and seed lifecycle, see
[`TESTING_POLICY.md`](TESTING_POLICY.md). For the complete operator guide, see
[`../patch-runner/README.md`](../patch-runner/README.md).
