#!/usr/bin/env python3
"""Run selected ProxyNightmare lifecycle scenarios under the C++ CPU monitor.

The caller must provide an isolated outer network namespace.  The ordinary
patch-runner lab then creates its named namespaces inside that disposable
namespace, so parallel lifecycle jobs cannot share links, routes or names.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import traceback

from cpu_monitor import Client

HERE = Path(__file__).resolve().parent

SCENARIOS = (
    "full_duplex_tiny_buffers",
    "client_receive_closed_upload",
    "client_abort_after_upload",
    "tls_client_hello_fin",
    "tls_scripted_handshake_close",
    "tls_idle_after_close_notify",
)


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def copy_lab(source, binary, work):
    for directory in ("bin", "runner/tests", "corpus", "src/etc/msg/en", "results"):
        (work / directory).mkdir(parents=True, exist_ok=True)
    os.symlink(binary, work / "bin/smithproxy")
    shutil.copy2(source / "tests/patch-runner/smithproxy.runner", work / "runner")
    shutil.copytree(source / "tests/patch-runner/harness", work / "runner/tests", dirs_exist_ok=True)
    shutil.copytree(source / "tests/patch-runner/corpus", work / "corpus", dirs_exist_ok=True)
    shutil.copy2(source / "tests/patch-runner/vendor/pplay.py", work)
    shutil.copy2(source / "etc/smithproxy.cfg", work / "src/etc")
    shutil.copytree(source / "etc/msg/en", work / "src/etc/msg/en", dirs_exist_ok=True)
    config = work / "src/etc/smithproxy.cfg"
    text = config.read_text()
    text = text.replace("allow_invalid_certs = FALSE", "allow_invalid_certs = TRUE")
    text = text.replace("allow_self_signed = FALSE", "allow_self_signed = TRUE")
    config.write_text(text)


def wait_for_lab(lab, console, work):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        text = console.read_text(errors="replace") if console.exists() else ""
        if "Smithproxy interactive lab READY" in text:
            pid_file = work / "data/proxy.pid"
            if pid_file.exists():
                return int(pid_file.read_text().strip())
        if lab.poll() is not None:
            raise RuntimeError(f"patch-runner lab exited with rc={lab.returncode}")
        time.sleep(.1)
    raise TimeoutError("patch-runner lab did not become ready")


def stop_stock_tls_origin():
    listing = subprocess.run(["ip", "netns", "pids", "sxr-origin"], text=True,
                             stdout=subprocess.PIPE, check=True).stdout.split()
    for pid in listing:
        try:
            command = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ")
        except FileNotFoundError:
            continue
        if b"origin.py" in command:
            os.kill(int(pid), signal.SIGTERM)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        check = subprocess.run(["ip", "netns", "exec", "sxr-origin", "ss", "-ltnH",
                                "sport = :443"], stdout=subprocess.PIPE)
        if not check.stdout:
            return
        time.sleep(.05)
    raise RuntimeError("stock TLS origin did not release port 443")


def scenario_path(name):
    local = HERE / "proxy-nightmare" / f"{name}.pn"
    if not local.exists():
        raise FileNotFoundError(f"Smithproxy-owned ProxyNightmare scenario is missing: {local}")
    return local


def expected_failures():
    path = HERE / "proxy-nightmare" / "expected-failures.json"
    values = json.loads(path.read_text())
    unknown = set(values) - set(SCENARIOS)
    if unknown:
        raise ValueError(f"expected failures name unknown scenarios: {sorted(unknown)}")
    for name, rule in values.items():
        if set(rule) != {"log_contains", "reason"} or not all(
                isinstance(value, str) and value for value in rule.values()):
            raise ValueError(f"invalid expected-failure rule: {name}")
    return values


def classify_functional(returncode, log_text, rule):
    if returncode == 0:
        return "XPASS" if rule else "PASS"
    if rule and rule["log_contains"] in log_text:
        return "XFAIL"
    return "FAIL"


def terminate(process, group=False):
    if process is None or process.poll() is not None:
        return
    try:
        (os.killpg(process.pid, signal.SIGTERM) if group else process.terminate())
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired:
        try:
            (os.killpg(process.pid, signal.SIGKILL) if group else process.kill())
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--smithproxy", type=Path, required=True)
    parser.add_argument("--monitor", type=Path, required=True)
    parser.add_argument("--proxy-nightmare", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    source, binary = args.source.resolve(), args.smithproxy.resolve()
    monitor_binary, pn_root = args.monitor.resolve(), args.proxy_nightmare.resolve()
    pn = pn_root / "build/pn"
    for executable in (binary, monitor_binary, pn):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            parser.error(f"missing executable: {executable}")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    work = output / "lab"
    copy_lab(source, binary, work)
    result = {
        "functional": "ERROR", "cpu": "ERROR", "scenarios": [],
        "proxy_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "monitor_sha256": hashlib.sha256(monitor_binary.read_bytes()).hexdigest(),
        "proxy_nightmare_sha256": hashlib.sha256(pn.read_bytes()).hexdigest(),
        "network_namespace": os.readlink("/proc/self/ns/net"),
    }
    expected = expected_failures()
    lab = monitor = None
    control = None
    active = False
    try:
        console = output / "lab-console.log"
        lab_env = os.environ.copy()
        lab_env.update(CLIENT_NS="sxr-client", SERVER_NS="sxr-origin", DATA_NS="sxr-data",
                       LAB_IN_IF="sxrpi", LAB_OUT_IF="sxrpo",
                       LAB_API_PORT=str(free_port()), LAB_CLI_PORT=str(free_port()),
                       RUN_MODE="1", BASE_TRAFFIC_TEST="0", CAPTURE_TEST="0")
        lab_log = console.open("w")
        lab = subprocess.Popen([str(work / "runner/tests/lab-test.sh"), str(work)],
                               env=lab_env, stdout=lab_log, stderr=subprocess.STDOUT,
                               start_new_session=True)
        proxy_pid = wait_for_lab(lab, console, work)
        result["proxy_pid"] = proxy_pid
        stop_stock_tls_origin()
        sockets = tempfile.TemporaryDirectory(prefix="pn-cpu-")
        monitor_log = (output / "monitor.log").open("w")
        monitor = subprocess.Popen([str(monitor_binary), "--socket", sockets.name + "/control.sock",
                                    "--output", str(output / "cpu"), "--control-timeout", "120"],
                                   stdout=monitor_log, stderr=subprocess.STDOUT)
        control = Client(sockets.name + "/control.sock")
        control.request("ATTACH", pid=proxy_pid)
        for name in SCENARIOS:
            path = scenario_path(name)
            if not path.exists():
                raise FileNotFoundError(path)
            # A PN scenario is one observable interval; its internal handshake,
            # close and sleep steps are not separate monitor phases.  Use the
            # loop detector for the whole interval instead of falsely calling
            # legitimate setup work "idle".
            mode = "bounded"
            limit = 80
            control.request("BEGIN", name=name, mode=mode, limit=limit)
            active = True
            started = time.monotonic()
            log_path = output / f"pn-{name}.log"
            with log_path.open("w") as log:
                completed = subprocess.run([str(pn), "run", str(path), "--trace"],
                                           stdout=log, stderr=subprocess.STDOUT)
            elapsed = time.monotonic() - started
            if elapsed < .65:
                time.sleep(.65 - elapsed)
            rule = expected.get(name)
            log_text = log_path.read_text(errors="replace")
            status = classify_functional(completed.returncode, log_text, rule)
            control.request("END", result=status)
            active = False
            result["scenarios"].append({"name": name, "functional": status,
                                        "rc": completed.returncode,
                                        "expected_failure": rule,
                                        "seconds": time.monotonic() - started,
                                        "cpu_mode": mode, "cpu_limit": limit})
            (output / "result.json").write_text(json.dumps(result, indent=2))
            print(name, status, flush=True)
        reply = control.request("FINISH")
        monitor.wait(timeout=10)
        report = json.loads((output / "cpu/report.json").read_text())
        if reply["verdict"] != report["verdict"] or report["implementation"] != "cpp":
            raise RuntimeError("CPU monitor reply/report mismatch")
        result["cpu"] = report["verdict"]
        result["functional"] = ("PASS" if all(item["functional"] in ("PASS", "XFAIL")
                                                for item in result["scenarios"]) else "FAIL")
        result["proxy_alive_at_finish"] = Path(f"/proc/{proxy_pid}").exists()
    except Exception:
        result["error"] = traceback.format_exc()
        if control and active:
            try:
                control.request("END", result="FAIL")
                control.request("FINISH")
            except Exception:
                pass
    finally:
        if control:
            control.close()
        terminate(monitor)
        terminate(lab, group=True)
        result["cleanup"] = {
            "lab_reaped": lab is None or lab.poll() is not None,
            "monitor_reaped": monitor is None or monitor.poll() is not None,
        }
        (output / "result.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2), flush=True)
    return 0 if result["functional"] == result["cpu"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
