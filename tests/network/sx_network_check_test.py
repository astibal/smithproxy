#!/usr/bin/env python3

import os
from pathlib import Path
import stat
import subprocess
import tempfile


SOURCE_ROOT = Path(__file__).resolve().parents[2]
SX_NETWORK = SOURCE_ROOT / "etc" / "smithproxy.startup.sh"


def executable(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


def run(action: str, environment: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SX_NETWORK), action, "default"],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="sx-network-check-") as temporary:
        root = Path(temporary)
        etc = root / "etc"
        run_dir = root / "run"
        bin_dir = root / "bin"
        etc.mkdir()
        run_dir.mkdir()
        bin_dir.mkdir()

        (etc / "smithproxy.cfg").write_text(
            "settings : {\n"
            "    accept_tproxy = TRUE;\n"
            "    accept_redirect = TRUE;\n"
            "    accept_socks = TRUE;\n"
            "    quic_workers = -1;\n"
            '    quic_port = "443";\n'
            "};\n"
        )
        (etc / "smithproxy.startup.cfg").write_text(
            'echo "legacy-startup-$2"\n'
        )

        executable(
            bin_dir / "iptables",
            "#!/bin/bash\n"
            "if [[ ${SX_TEST_DRIFT:-0} == 1 && \" $* \" == *\" -S SX.default \"* ]]; then\n"
            "    exit 1\n"
            "fi\n"
            "exit 0\n",
        )
        executable(bin_dir / "ip6tables", (bin_dir / "iptables").read_text())
        executable(
            bin_dir / "ip",
            "#!/bin/bash\n"
            "if [[ \" $* \" == *\" rule show \"* ]]; then\n"
            "    echo '100: from all fwmark 0x1/0x1 lookup 100'\n"
            "elif [[ \" $* \" == *\" route show table 100 \"* ]]; then\n"
            "    if [[ \" $* \" == *\" -6 \"* ]]; then\n"
            "        echo 'local ::/0 dev lo proto kernel metric 256 pref medium'\n"
            "    else\n"
            "        echo 'local 0.0.0.0/0 dev lo scope host'\n"
            "    fi\n"
            "fi\n",
        )
        executable(bin_dir / "sysctl", "#!/bin/bash\necho 1\n")

        log_file = root / "startup.log"
        environment = os.environ.copy()
        environment.update(
            {
                "SMITHPROXY_ETC_DIR": str(etc),
                "SMITHPROXY_RUN_DIR": str(run_dir),
                "SMITHPROXY_NETWORK_LOG": str(log_file),
                "IPTABLES_CMD": str(bin_dir / "iptables"),
                "IP6TABLES_CMD": str(bin_dir / "ip6tables"),
                "IP_CMD": str(bin_dir / "ip"),
                "SYSCTL_CMD": str(bin_dir / "sysctl"),
            }
        )

        healthy = run("check", environment)
        assert healthy.returncode == 0, healthy.stdout
        assert "state is healthy" in healthy.stdout

        first_watch = run("watch", environment)
        assert first_watch.returncode == 0, first_watch.stdout
        assert "state drift" not in log_file.read_text()

        environment["SX_TEST_DRIFT"] = "1"
        drift = run("check", environment)
        assert drift.returncode != 0
        assert "missing ipv4 mangle chain SX.default" in drift.stdout

        changed_watch = run("watch", environment)
        assert changed_watch.returncode == 0, changed_watch.stdout
        changed_log = log_file.read_text()
        assert changed_log.count("state drift detected") == 1

        repeated_watch = run("watch", environment)
        assert repeated_watch.returncode == 0, repeated_watch.stdout
        repeated_log = log_file.read_text()
        assert repeated_log == changed_log, repeated_log

        environment.pop("SX_TEST_DRIFT")
        recovered_watch = run("watch", environment)
        assert recovered_watch.returncode == 0, recovered_watch.stdout
        assert log_file.read_text().count("state recovered") == 1

        # A valid native archive supplies both main and startup configuration.
        # Change the legacy files afterwards to prove they are not mixed in.
        native_main = (etc / "smithproxy.cfg").read_text().replace(
            "quic_workers = -1", "quic_workers = 1"
        )
        (etc / "native.cfg").write_text(native_main)
        (etc / "native.startup.cfg").write_text(
            'echo "native-startup-$2"\n'
        )
        archive = etc / "smithproxy.cftar"
        created = subprocess.run(
            [
                environment["SMITHPROXY_CFTAR_CMD"],
                "create",
                "--config",
                str(etc / "native.cfg"),
                "--startup",
                str(etc / "native.startup.cfg"),
                "--output",
                str(archive),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        assert created.returncode == 0, created.stdout

        environment["NETWORK_FORCE_LOG"] = "1"
        native = run("check", environment)
        environment.pop("NETWORK_FORCE_LOG")
        assert native.returncode == 0, native.stdout
        assert "native-startup-before" in native.stdout
        assert "QUIC interception enabled" in native.stdout
        assert "legacy-startup" not in native.stdout

        # Presence controls fallback. A broken native archive must stop the
        # network service instead of resurrecting the legacy files.
        archive.write_text("broken archive")
        environment["NETWORK_FORCE_LOG"] = "1"
        broken = run("check", environment)
        environment.pop("NETWORK_FORCE_LOG")
        assert broken.returncode != 0, broken.stdout
        assert "Cannot load validated network configuration" in broken.stdout

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
