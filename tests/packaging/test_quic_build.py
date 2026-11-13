#!/usr/bin/env python3
"""Exercise backend propagation without installing packages or invoking Docker."""
import json
import runpy
from unittest.mock import patch
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class QuicBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.bin = self.work / "bin"
        self.bin.mkdir()
        self.log = self.work / "calls.jsonl"
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
                        COMMAND_LOG=str(self.log))
        self.env.pop("SMITHPROXY_ENABLE_NGTCP2", None)
        for name in ("apt-get", "apk", "dnf", "zypper", "cmake", "id", "uname"):
            script = self.bin / name
            script.write_text(f"#!{sys.executable}\n" + '''import json, os, sys
from pathlib import Path
name = Path(sys.argv[0]).name
if name in ('id', 'uname'):
    print('0' if name == 'id' else 'Linux')
else:
    with open(os.environ['COMMAND_LOG'], 'a') as out:
        out.write(json.dumps([name, *sys.argv[1:]]) + '\\n')
    if 'install' in sys.argv or 'add' in sys.argv:
        sys.exit(int(os.environ.get('INSTALL_FAILURE', '0')))
''')
            script.chmod(0o755)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def install(self, distro, backend=None):
        release = self.work / "os-release"
        release.write_text(f"ID={distro}\nVERSION_ID=test\n")
        # Redirect only the OS identity file in an isolated script copy; all
        # package-manager invocations execute unchanged against recording stubs.
        script = self.work / "linux-deps.sh"
        script.write_text((ROOT / "tools/linux-deps.sh").read_text().replace(
            "/etc/os-release", str(release)))
        if backend is not None:
            self.env["SMITHPROXY_ENABLE_NGTCP2"] = backend
        return subprocess.run(["sh", str(script)], env=self.env, capture_output=True, text=True)

    def test_installers_use_system_tls_without_system_ngtcp2(self):
        packages = {
            "ubuntu": "libssl-dev", "alpine": "openssl-dev",
            "fedora": "openssl-devel",
            "opensuse-tumbleweed": "libopenssl-devel",
            "rocky": "openssl-devel",
        }
        for distro, tls_package in packages.items():
            for backend in (None, "OFF"):
                with self.subTest(distro=distro, backend=backend):
                    self.env.pop("SMITHPROXY_ENABLE_NGTCP2", None)
                    self.log.unlink(missing_ok=True)
                    result = self.install(distro, backend)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    args = [arg for call in self.calls() for arg in call]
                    self.assertIn(tls_package, args)
                    self.assertFalse(any("ngtcp2" in arg for arg in args))

    def test_missing_dependency_fails_without_retrying_another_backend(self):
        self.env["INSTALL_FAILURE"] = "42"
        result = self.install("ubuntu")
        self.assertEqual(result.returncode, 42)
        installs = [call for call in self.calls() if "install" in call]
        self.assertEqual(len(installs), 1)
        self.assertIn("libssl-dev", installs[0])
        self.assertFalse(any("ngtcp2" in arg for arg in installs[0]))

    def test_invalid_backend_fails_before_package_or_build_operations(self):
        result = self.install("ubuntu", "auto")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])
        result = subprocess.run(["bash", str(ROOT / "tools/linux-build.sh")],
                                env=self.env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_build_wrapper_passes_default_and_explicit_off_to_cmake(self):
        for backend in (None, "OFF"):
            with self.subTest(backend=backend):
                self.log.unlink(missing_ok=True)
                self.env.pop("SMITHPROXY_ENABLE_NGTCP2", None)
                if backend:
                    self.env["SMITHPROXY_ENABLE_NGTCP2"] = backend
                result = subprocess.run(["bash", str(ROOT / "tools/linux-build.sh")],
                                        env=self.env, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                configure = next(call for call in self.calls() if "-S" in call)
                self.assertIn(f"-DSMITHPROXY_ENABLE_NGTCP2={backend or 'ON'}", configure)

    def test_debian_profile_selects_backend_for_release_and_debug(self):
        for directory in ("debian-0.9", "debian-0.9-debug"):
            for profile, backend in (("", "ON"), ("pkg.smithproxy.openssl-quic", "OFF")):
                with self.subTest(directory=directory, profile=profile):
                    rules = ROOT / "tools/pkg-scripts/deb" / directory / "rules"
                    result = subprocess.run(["make", "-n", "-f", str(rules),
                                             "override_dh_auto_configure",
                                             f"DEB_BUILD_PROFILES={profile}"],
                                            capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn(f"-DSMITHPROXY_ENABLE_NGTCP2={backend}", result.stdout)

    def test_docker_builder_propagates_failure(self):
        # Dependency failures must escape the per-host builder, not look successful.
        builder = runpy.run_path(str(ROOT / "tools/sx-builder.py"))
        for host in ("localhost", "test-host"):
            with self.subTest(host=host):
                failure = subprocess.CalledProcessError(42, "mock build")
                with patch("subprocess.run", side_effect=failure) as run:
                    with self.assertRaises(subprocess.CalledProcessError):
                        builder["run_build"](host, ["Dockerfile"], arg_ngtcp2="ON")
                    self.assertTrue(run.call_args_list[0].kwargs["check"])
                    if host == "localhost":
                        self.assertIn('; docker build', run.call_args_list[0].args[0])
                    self.assertIn("SMITHPROXY_ENABLE_NGTCP2=ON", run.call_args_list[0].args[0])


if __name__ == "__main__":
    unittest.main()
