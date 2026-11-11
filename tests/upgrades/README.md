# CFtar upgrade gate

This opt-in process suite upgrades a configuration **saved by a real master
binary** to the supplied TLC binary. It does not install either version or alter
host `/etc` configuration. Each run requires a fresh output directory.

Run as root on a disposable Linux test host with `unshare`, `mount`, `ip`, Python
3, and the runtime dependencies of both binaries. The launcher creates private
mount, network, and PID namespaces, makes mount propagation private, and enables
only loopback. Read-only mount experiments are confined to those namespaces.
A private tmpfs isolates `/tmp` runtime files, and neighbor/capture state is redirected
into the scenario directory. Choose output outside `/tmp` (for example `/var/tmp`);
the host output directory remains available after the namespace exits.

```sh
python3 tests/upgrades/cftar_upgrade.py \
  --master /absolute/master-build/smithproxy \
  --master-source /absolute/master-source \
  --master-revision MASTER_COMMIT \
  --tlc /absolute/tlc-build/smithproxy \
  --tlc-revision TLC_COMMIT_OR_COMMIT_PLUS_PATCH \
  --cftar /absolute/tlc-build/smithproxy-cftar \
  --output /var/tmp/cftar-upgrade-unique-run
```

`--master-source` must match the master binary. The CLI helper comes from this
suite's source checkout. Build both binaries from recorded commits first; the
suite records binary hashes and its own script hash in `builds.json`.

The seed step starts master, creates `upgrade_marker` with CIDR `192.0.2.0/24`,
verifies it through CLI, and issues `save config`. Scenario copies relocate only
fixture paths and listener ports. Successful scenarios verify both the saved
object and actual SOCKS forwarding through the running TLC process.

## Scenarios

- initial migration and two cold restarts;
- default `/etc/smithproxy` layout with legacy-tree retirement, under a private `/etc` mount;
- custom `.cfg`, extensionless, and alternative-suffix configuration names;
- existing backup, directory at backup name, and symlink at backup name;
- read-only migration directory and successful retry;
- actual ENOSPC on an isolated tmpfs and successful retry after freeing space;
- read-only legacy retirement and successful retry without native config loss;
- corrupt native archive with valid legacy config (no fallback);
- missing native archive after successful retirement (no `.old` fallback);
- invalid native certificate or missing native template (no legacy retirement on failed resource loading);
- native reload with a stale `.cfg` created during runtime (no startup cleanup);
- config-check without persistent file mutations;
- directory instead of archive;
- symlink instead of legacy config (no following or deletion of its target);
- entirely missing configuration;
- explicit `.cftar` path;
- SIGKILL after activation, then restart from the same archive;
- missing migration resource and recovery after restoring it.

## Evidence and interpretation

Every scenario writes `before.json` and `after.json` with file hashes, sizes and
modes, stdout/stderr logs, CLI transcripts, and exit status. `results.json`
contains individual outcomes and timings. Test keys and certificates are fixture
material; still treat the artifact directory as configuration data.

A read-only retirement scenario deliberately allows continued service using the
valid native archive, but requires a diagnostic and unchanged source files. Its
retry must retire the stale legacy file. A failed migration must preserve its
source; a process crash is not accepted as graceful failure. Existing archive
corruption must never resurrect legacy policy.

This is not a power-loss or storage-controller durability test. SIGKILL tests
process failure after completed activation, not every individual instruction in
migration. It also does not exercise package-manager scripts or production
traffic load. Keep the full P8 gate separate.
