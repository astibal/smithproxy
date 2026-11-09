#!/usr/bin/env python3
"""Regression tests for private-key creation and installation permissions."""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import tempfile


def require_mode(path: Path, expected: int) -> None:
    actual = stat.S_IMODE(path.stat().st_mode)
    if actual != expected:
        raise AssertionError(f"{path} has mode {actual:04o}, expected {expected:04o}")


def load_sxyca(source: Path):
    module_path = source / "src/infra/sslca/sxyca.py"
    spec = importlib.util.spec_from_file_location("sxyca_under_test", module_path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"cannot load {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_save_key(source: Path, work: Path) -> None:
    sxyca = load_sxyca(source)
    sxyca.SETTINGS["path"] = str(work)
    key = sxyca.generate_ec_key(sxyca.ec.SECP256R1())
    target = work / "generated-key.pem"

    previous_umask = os.umask(0o022)
    try:
        sxyca.save_key(key, target.name)
        require_mode(target, 0o600)

        target.chmod(0o644)
        sxyca.save_key(key, target.name)
        require_mode(target, 0o600)

        sentinel = work / "sentinel"
        sentinel.write_text("must remain unchanged")
        target.unlink()
        target.symlink_to(sentinel)
        sxyca.save_key(key, target.name)
        if target.is_symlink():
            raise AssertionError("save_key followed the destination symlink")
        if sentinel.read_text() != "must remain unchanged":
            raise AssertionError("save_key modified the symlink target")
        require_mode(target, 0o600)
    finally:
        os.umask(previous_umask)

    if list(work.glob(".private-key-*")):
        raise AssertionError("save_key left a temporary file behind")


def run(command: list[str], expected_success: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        timeout=30,
    )
    if (completed.returncode == 0) != expected_success:
        raise AssertionError(
            f"unexpected exit status {completed.returncode}: {' '.join(command)}\n"
            f"{completed.stdout}"
        )
    return completed


def test_install_helper(source: Path, work: Path) -> None:
    project = work / "install-project"
    build = work / "install-build"
    prefix = work / "install-root"
    project.mkdir()
    source_key = project / "source-key.pem"
    source_key.write_text("packaged key")
    source_key.chmod(0o644)
    (project / "CMakeLists.txt").write_text(
        "cmake_minimum_required(VERSION 3.14)\n"
        "project(private_key_install NONE)\n"
        f'include("{source / "helpers.cmake"}")\n'
        "install(DIRECTORY DESTINATION keys)\n"
        f'install_secret_if_not_exists("{source_key}" "keys")\n'
    )

    run(["cmake", "-S", str(project), "-B", str(build),
         f"-DCMAKE_INSTALL_PREFIX={prefix}"])
    run(["cmake", "--install", str(build)])
    installed = prefix / "keys/source-key.pem"
    require_mode(installed, 0o600)

    installed.write_text("deployed key")
    installed.chmod(0o644)
    run(["cmake", "--install", str(build)])
    require_mode(installed, 0o600)
    if installed.read_text() != "deployed key":
        raise AssertionError("upgrade replaced the deployed private key")

    sentinel = work / "install-sentinel"
    sentinel.write_text("must remain unchanged")
    installed.unlink()
    installed.symlink_to(sentinel)
    result = run(["cmake", "--install", str(build)], expected_success=False)
    if "Refusing private-key symlink" not in result.stdout:
        raise AssertionError(f"installer failed for an unexpected reason:\n{result.stdout}")
    if sentinel.read_text() != "must remain unchanged":
        raise AssertionError("installer modified the symlink target")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="smithproxy-private-keys-") as name:
        work = Path(name)
        test_save_key(args.source.resolve(), work)
        test_install_helper(args.source.resolve(), work)
    print("PASS: private keys are created, replaced, and installed safely")


if __name__ == "__main__":
    main()
