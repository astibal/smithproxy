#!/usr/bin/env python3
"""Exercise the installed-style CFtar tool against real archive files."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time


def invoke(binary: Path, arguments: list[str], expected: int = 0,
           needle: str | None = None, input_text: str | None = None,
           environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        [str(binary), *arguments], input=input_text, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, timeout=30,
        env={**os.environ, **(environment or {})})
    if result.returncode != expected or (needle is not None and needle not in result.stdout):
        raise AssertionError(
            f"{arguments!r}: expected rc={expected} and {needle!r}, "
            f"got rc={result.returncode}:\n{result.stdout}")
    return result


def assert_private_regular(path: Path) -> None:
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise AssertionError(f"{path} is not a private regular file: {metadata.st_mode:o}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--source", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    source = args.source.resolve()

    with tempfile.TemporaryDirectory(prefix="smithproxy-cftar-e2e-") as temporary:
        root = Path(temporary)
        archive = root / "test.cftar"
        config = source / "etc/smithproxy.cfg"
        startup = source / "etc/smithproxy.startup.cfg"
        resource = root / "resource.bin"
        resource.write_bytes(b"binary\x00resource\xff")
        text_resource = root / "message.txt"
        text_resource.write_text("editable message\n", encoding="utf-8")

        invoke(binary, ["create", "--config", str(config), "--startup", str(startup),
                        "--file", f"messages/en/sample.bin={resource}",
                        "--file", f"messages/en/editable.txt={text_resource}",
                        "--output", str(archive)], needle="Created")
        assert_private_regular(archive)
        invoke(binary, ["verify", str(archive)], needle="valid Smithproxy CfgTar")
        invoke(binary, ["inspect", str(archive)], needle="entries: 5")
        invoke(binary, ["list", str(archive), "messages/"], needle="messages/en/sample.bin")
        result = subprocess.run(
            [str(binary), "get", str(archive), "messages/en/sample.bin"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        if result.returncode != 0 or result.stdout != resource.read_bytes():
            raise AssertionError("get did not preserve binary resource bytes")

        imported = root / "imported.txt"
        imported.write_text("first generation\n", encoding="utf-8")
        invoke(binary, ["resource", "import", str(archive), "scripts/check.macro",
                        str(imported), "executable"], needle="Imported")
        recovery = Path(str(archive) + ".previous.bak.cftar")
        assert_private_regular(recovery)
        invoke(binary, ["verify", str(recovery)])

        exported = root / "exported.txt"
        invoke(binary, ["resource", "export", str(archive), "scripts/check.macro",
                        str(exported)], needle="Exported")
        assert_private_regular(exported)
        if exported.read_bytes() != imported.read_bytes():
            raise AssertionError("resource export changed bytes")
        invoke(binary, ["resource", "remove", str(archive), "scripts/check.macro"],
               needle="Removed")
        invoke(binary, ["get", str(archive), "scripts/check.macro"], expected=1,
               needle="CfgTar entry not found")

        editor = root / "editor"
        editor.write_text("#!/bin/sh\nprintf 'edited message\\n' > \"$1\"\n", encoding="utf-8")
        editor.chmod(0o700)
        shell_export = root / "shell-export.bin"

        # The interactive shell is only another view of the same offline
        # session. Exercise its complete administrative workflow without
        # touching a running Smithproxy instance.
        shell = invoke(
            binary, ["interactive", str(archive)], input_text=(
                "help\n"
                "help inspect\n"
                "help absent\n"
                "inspect\n"
                "list messages/\n"
                "show messages/en/editable.txt\n"
                "show messages/en/sample.bin\n"
                f"resource export messages/en/sample.bin {shell_export}\n"
                f"resource import messages/en/staged.txt {imported}\n"
                "resource remove messages/en/editable.txt\n"
                "diff\n"
                "discard\n"
                "edit messages/en/editable.txt\n"
                "diff\n"
                "validate\n"
                "save\n"
                "save\n"
                "exposures\n"
                "expose messages/en\n"
                "exposures\n"
                "close exposure 1\n"
                "expose messages/en/sample.bin\n"
                "close exposures all\n"
                "close exposure invalid\n"
                "unknown command\n"
                "quit\n"),
            environment={"VISUAL": str(editor)})
        for expected_text in (
                "working state: clean", "added  messages/en/staged.txt",
                "removed  messages/en/editable.txt", "modified  messages/en/editable.txt",
                "working archive reset", "working archive is valid",
                "archive saved atomically", "working archive is unchanged",
                "binary resource cannot be shown", "resource exported",
                "no active exposures", "exposure closed", "all exposures closed",
                "% unknown help path", "% unknown command"):
            if expected_text not in shell.stdout:
                raise AssertionError(f"interactive output lacks {expected_text!r}")
        if shell_export.read_bytes() != resource.read_bytes():
            raise AssertionError("interactive export changed binary bytes")

        dirty_exit = invoke(
            binary, ["interactive", str(archive)], input_text=(
                f"resource import messages/en/abandoned.txt {imported}\n"
                "quit\n"
                "quit force\n"))
        if "unsaved changes" not in dirty_exit.stdout:
            raise AssertionError("interactive shell did not protect dirty quit")

        # Keep one administrator's session open while another process commits
        # a newer generation. The stale session must preserve the winner and
        # refuse its own save instead of silently overwriting it.
        stale = subprocess.Popen(
            [str(binary), "interactive", str(archive)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        assert stale.stdin is not None
        stale.stdin.write("inspect\n")
        stale.stdin.flush()
        time.sleep(0.1)
        invoke(binary, ["resource", "import", str(archive),
                        "messages/en/external.txt", str(imported)])
        stale.stdin.write(
            f"resource import messages/en/stale.txt {imported}\nsave\nquit force\n")
        stale.stdin.flush()
        stale_output, _ = stale.communicate(timeout=30)
        if stale.returncode != 0 or "archive changed since this session opened" not in stale_output:
            raise AssertionError(f"stale interactive save was not rejected:\n{stale_output}")
        invoke(binary, ["get", str(archive), "messages/en/external.txt"],
               needle="first generation")
        invoke(binary, ["get", str(archive), "messages/en/stale.txt"], expected=1,
               needle="CfgTar entry not found")

        # Repeat the stale-session scenario with an uncooperative filesystem
        # replacement that bypasses both CFtar locks. This models an
        # administrator installing a hand-built archive with mv(1).
        manual_archive = root / "manual-replacement.cftar"
        invoke(binary, ["create", "--config", str(config), "--startup", str(startup),
                        "--file", f"messages/en/manual.txt={imported}",
                        "--file", f"messages/en/sample.bin={resource}",
                        "--output", str(manual_archive)], needle="Created")
        manual_stale = subprocess.Popen(
            [str(binary), "interactive", str(archive)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        assert manual_stale.stdin is not None
        manual_stale.stdin.write(
            f"resource import messages/en/manual-stale.txt {imported}\n")
        manual_stale.stdin.flush()
        time.sleep(0.1)
        os.replace(manual_archive, archive)
        manual_stale.stdin.write("save\nquit force\n")
        manual_stale.stdin.flush()
        manual_output, _ = manual_stale.communicate(timeout=30)
        if (manual_stale.returncode != 0 or
                "archive changed since this session opened" not in manual_output):
            raise AssertionError(
                f"manual replacement was overwritten by a stale session:\n{manual_output}")
        invoke(binary, ["get", str(archive), "messages/en/manual.txt"],
               needle="first generation")
        invoke(binary, ["get", str(archive), "messages/en/manual-stale.txt"],
               expected=1, needle="CfgTar entry not found")

        # A fresh session starts from the manually installed generation and
        # remains fully usable after rejecting the stale writer.
        invoke(binary, ["resource", "import", str(archive),
                        "messages/en/manual-retry.txt", str(imported)], needle="Imported")
        invoke(binary, ["get", str(archive), "messages/en/manual-retry.txt"],
               needle="first generation")

        # Open several administrative sessions on exactly the same generation,
        # stage a distinct resource in each one, then release all saves at once.
        # One session may publish; every stale peer must refuse to overwrite it.
        contenders: list[tuple[subprocess.Popen[str], str]] = []
        for index in range(6):
            resource_path = f"messages/en/concurrent-{index}.txt"
            process = subprocess.Popen(
                [str(binary), "interactive", str(archive)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True)
            assert process.stdin is not None
            process.stdin.write(
                f"inspect\nresource import {resource_path} {imported}\n")
            process.stdin.flush()
            contenders.append((process, resource_path))

        # Commands are line-oriented but stdout is buffered through a pipe.
        # A short barrier gives every process time to open and stage before any
        # process is allowed to publish its private generation.
        time.sleep(0.2)
        for process, _ in contenders:
            assert process.stdin is not None
            process.stdin.write("save\nquit force\n")
            process.stdin.flush()

        outcomes: list[tuple[str, str]] = []
        for process, resource_path in contenders:
            output, _ = process.communicate(timeout=30)
            if process.returncode != 0:
                raise AssertionError(
                    f"concurrent shell failed for {resource_path}:\n{output}")
            outcomes.append((resource_path, output))

        winners = [path for path, output in outcomes
                   if "archive saved atomically" in output]
        if len(winners) != 1:
            raise AssertionError(
                f"expected one concurrent winner, got {len(winners)}:\n" +
                "\n---\n".join(output for _, output in outcomes))
        for path, output in outcomes:
            if path not in winners and "archive changed since this session opened" not in output:
                raise AssertionError(
                    f"concurrent loser did not report stale state for {path}:\n{output}")

        invoke(binary, ["verify", str(archive)], needle="valid Smithproxy CfgTar")
        invoke(binary, ["verify", str(recovery)], needle="valid Smithproxy CfgTar")
        invoke(binary, ["get", str(archive), winners[0]], needle="first generation")

        # A rejected transaction remains an ordinary retryable administration
        # action. Reopen the winning generation and apply each missing resource.
        for resource_path, _ in outcomes:
            if resource_path not in winners:
                invoke(binary, ["resource", "import", str(archive),
                                resource_path, str(imported)], needle="Imported")
        for resource_path, _ in outcomes:
            invoke(binary, ["get", str(archive), resource_path],
                   needle="first generation")
        invoke(binary, ["verify", str(archive)], needle="valid Smithproxy CfgTar")

        malformed = root / "malformed.cftar"
        malformed.write_bytes(b"not a tar archive")
        invoke(binary, ["verify", str(malformed)], expected=1, needle="smithproxy-cftar:")
        invoke(binary, ["create", "--config", str(config), "--output", str(root / "bad.cftar")],
               expected=1, needle="main and startup input paths are required")
        invoke(binary, ["resource", "import", str(archive), "smithproxy.cfg", str(imported)],
               expected=1, needle="not a resource path")
        invoke(binary, ["resource", "export", str(archive), "messages/en/sample.bin",
                        str(exported)], expected=1, needle="cannot create export file")
        invoke(binary, ["unknown"], expected=2, needle="Usage:")

    print("PASS: CFtar process create, inspect, mutation, recovery and failure paths")


if __name__ == "__main__":
    main()
