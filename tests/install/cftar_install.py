#!/usr/bin/env python3
"""Verify the package-time contract for the native configuration archive."""

from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import tempfile


def install(build: Path, root: Path, expected: int = 0) -> subprocess.CompletedProcess[str]:
    """Install into an isolated package root and require the expected result."""
    result = subprocess.run(
        ["cmake", "-E", "env", f"DESTDIR={root}", "cmake", "--install", str(build)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode != expected:
        raise AssertionError(
            f"install returned {result.returncode}, expected {expected}:\n{result.stdout}"
        )
    return result


def config_dir(root: Path) -> Path:
    """Create and return the staged system configuration directory."""
    directory = root / "etc" / "smithproxy"
    directory.mkdir(parents=True)
    return directory


def verify_archive(cftar: Path, archive: Path) -> None:
    """Require the installed archive to pass the public CFtar verifier."""
    result = subprocess.run(
        [str(cftar), "verify", str(archive)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"installed archive is invalid:\n{result.stdout}")


def test_fresh_install(build: Path, cftar: Path, root: Path) -> None:
    """A new installation receives one complete native configuration archive."""
    install(build, root)
    directory = root / "etc" / "smithproxy"
    archive = directory / "smithproxy.cftar"

    assert archive.is_file()
    assert archive.stat().st_mode & 0o777 == 0o600
    assert not (directory / "smithproxy.cfg").exists()
    assert not (directory / "smithproxy.startup.cfg").exists()
    assert not (directory / "certs").exists()
    assert not (directory / "msg").exists()
    verify_archive(cftar, archive)


def test_legacy_upgrade(build: Path, root: Path) -> None:
    """A package upgrade leaves legacy input for the runtime migration."""
    directory = config_dir(root)
    legacy = directory / "smithproxy.cfg"
    legacy.write_text("legacy sentinel\n")

    install(build, root)

    assert legacy.read_text() == "legacy sentinel\n"
    assert not (directory / "smithproxy.cftar").exists()


def test_native_upgrade(build: Path, root: Path) -> None:
    """An existing native archive is preserved and its permissions are repaired."""
    directory = config_dir(root)
    archive = directory / "smithproxy.cftar"
    archive.write_text("native sentinel\n")
    archive.chmod(0o644)

    install(build, root)

    assert archive.read_text() == "native sentinel\n"
    assert archive.stat().st_mode & 0o777 == 0o600


def test_symlink_rejected(build: Path, root: Path) -> None:
    """A package install cannot overwrite a native archive through a symlink."""
    directory = config_dir(root)
    target = root / "target"
    target.write_text("target sentinel\n")
    (directory / "smithproxy.cftar").symlink_to(target)

    result = install(build, root, expected=1)

    assert "Refusing native configuration symlink" in result.stdout
    assert target.read_text() == "target sentinel\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--cftar", type=Path, required=True)
    args = parser.parse_args()

    build = args.build.resolve()
    cftar = args.cftar.resolve()
    with tempfile.TemporaryDirectory(prefix="smithproxy-cftar-install-") as temporary:
        root = Path(temporary)
        test_fresh_install(build, cftar, root / "fresh")
        test_legacy_upgrade(build, root / "legacy")
        test_native_upgrade(build, root / "native")
        test_symlink_rejected(build, root / "symlink")

    print("PASS: fresh and upgrade CFtar installation contracts")


if __name__ == "__main__":
    main()
