#!/usr/bin/env python3
"""Isolated A:B throughput comparison using the existing native H3 harness.

Requires root, iproute2, iptables, tcpdump, and the built native endpoints. Only
namespaces created by this invocation are changed. FORWARD DROP prevents bypass.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import shutil
import tempfile
import subprocess
import time


def run(*args):
    """Run a required setup/check command, retaining stderr on failure."""
    return subprocess.run(list(map(str, args)), check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", type=Path, required=True)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--backend", choices=("ngtcp2", "openssl"), required=True)
    parser.add_argument("--family", choices=(4, 6), type=int, default=4)
    parser.add_argument("--bytes", type=int, default=134217728)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--concurrency", default="1,4")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("network namespaces require root")
    args.output.mkdir(parents=True, exist_ok=False)
    out = args.output.resolve()
    source = Path(__file__).resolve().parents[3]
    harness = source / "tests/patch-runner/harness"
    prefix = f"qng{os.getpid()}"
    c, p, o = (prefix + role for role in ("c", "p", "o"))
    namespaces, processes, logs = [], [], []
    capture_directory = tempfile.TemporaryDirectory(prefix="quic-ngtcp2-capture-", dir="/var/tmp")
    capture_path = Path(capture_directory.name) / "tuple.pcap"

    def ns(namespace, *command):
        return run("ip", "netns", "exec", namespace, *command)

    def start(namespace, name, *command):
        log = (out / f"{name}.log").open("w")
        logs.append(log)
        proc = subprocess.Popen(["ip", "netns", "exec", namespace, *map(str, command)],
                                stdout=log, stderr=subprocess.STDOUT)
        processes.append(proc)
        return proc

    def ready(process, name):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(f"{name} exited: {(out / (name + '.log')).read_text()}")
            if "READY" in (out / f"{name}.log").read_text():
                return
            time.sleep(.05)
        raise RuntimeError(f"{name} did not become ready")

    try:
        for namespace in (c, p, o):
            run("ip", "netns", "add", namespace)
            namespaces.append(namespace)
            ns(namespace, "ip", "link", "set", "lo", "up")
        for left, right, left_if, right_if in ((c, p, "c0", "p0"), (p, o, "p1", "o0")):
            ns(left, "ip", "link", "add", left_if, "type", "veth", "peer", "name", right_if)
            ns(left, "ip", "link", "set", right_if, "netns", right)
            ns(left, "ip", "link", "set", left_if, "up")
            ns(right, "ip", "link", "set", right_if, "up")
        for namespace, iface, ip4, ip6 in ((c, "c0", "198.18.10.2", "fd00:10::2"),
                (p, "p0", "198.18.10.1", "fd00:10::1"),
                (p, "p1", "198.18.20.1", "fd00:20::1"), (o, "o0", "198.18.20.2", "fd00:20::2")):
            ns(namespace, "ip", "addr", "add", ip4 + "/24", "dev", iface)
            ns(namespace, "ip", "-6", "addr", "add", ip6 + "/64", "dev", iface, "nodad")
        for namespace, via4, via6 in ((c, "198.18.10.1", "fd00:10::1"), (o, "198.18.20.1", "fd00:20::1")):
            ns(namespace, "ip", "route", "add", "default", "via", via4)
            ns(namespace, "ip", "-6", "route", "add", "default", "via", via6)
        ns(p, "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1",
           "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.p0.rp_filter=0", "net.ipv4.conf.p1.rp_filter=0")
        for family, table, any_address in (("-4", "iptables", "0.0.0.0/0"), ("-6", "ip6tables", "::/0")):
            ns(p, table, "-P", "FORWARD", "DROP")
            ns(p, table, "-t", "mangle", "-A", "PREROUTING", "-i", "p0", "-p", "udp",
               "--dport", "443", "-j", "TPROXY", "--on-port", "443", "--tproxy-mark", "1/1")
            ns(p, "ip", family, "rule", "add", "fwmark", "1", "lookup", "100")
            ns(p, "ip", family, "route", "add", "local", any_address, "dev", "lo", "table", "100")
        cert, key = out / "cert.pem", out / "key.pem"
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=origin.runner.lab", "-addext", "subjectAltName=DNS:origin.runner.lab",
            "-keyout", key, "-out", cert)
        origin = start(o, "origin", "python3", harness / "native-h3-origin.py",
            "--server", args.native / "bin/h3-server", "--certificate", cert, "--key", key,
            "--directory", out / "payload", "--pid-file", out / "origin-pids.json",
            "--bytes", args.bytes, "--workers", "4")
        ready(origin, "origin")
        egress = "198.18.20.1" if args.family == 4 else "fd00:20::1"
        host = "198.18.20.2" if args.family == 4 else "fd00:20::2"
        proxy = start(p, "proxy", args.node, "--insecure-lab", args.backend,
                      cert, key, egress, host, args.family, "4")
        ready(proxy, "proxy")
        maps = Path(f"/proc/{proxy.pid}/maps").read_text()
        (out / "runtime-maps.txt").write_text(maps)
        (out / "parameters.json").write_text(json.dumps(vars(args), default=str, indent=2))
        # Capture only the beginning: full-payload capture would distort throughput.
        capture = start(c, "capture", "env", "-u", "LD_LIBRARY_PATH", "tcpdump", "-Z", "root", "-n", "-U", "-i", "c0",
                        "-c", "40", "-s", "128", "-w", capture_path, "udp", "port", "443")
        time.sleep(.15)
        driver = start(c, "measurement", "python3", harness / "tls-transfer.py", "--protocol", "h3",
            "--h3-client", args.native / "bin/h3-client", "--host", host, "--ca-file", cert,
            "--bytes", args.bytes, "--repeats", args.repeats, "--concurrency", args.concurrency,
            "--pid", proxy.pid, "--origin-pid-file", out / "origin-pids.json", "--timeout", "30",
            "--output", out / "throughput.json")
        if driver.wait(timeout=600):
            raise RuntimeError((out / "measurement.log").read_text())
        if capture.poll() is None:
            capture.send_signal(signal.SIGINT)
            capture.wait(timeout=5)
        packets = run("env", "-u", "LD_LIBRARY_PATH", "tcpdump", "-nn", "-r", capture_path)
        shutil.copy2(capture_path, out / "tuple.pcap")
        (out / "tuple.txt").write_text(packets)
        replies = [line for line in packets.splitlines() if f"{host}.443 > " in line]
        if not replies:
            raise RuntimeError("missing transparent reply from original IP:443")
        for table in ("iptables", "ip6tables"):
            (out / f"{table}.txt").write_text(ns(p, table, "-nvL", "FORWARD"))
        # The benchmark checks payload length, bytes, HTTP status and stream end.
        print(f"PASS backend={args.backend} IPv{args.family} transparent_replies={len(replies)} results={out}")
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        for log in logs:
            log.close()
        capture_directory.cleanup()
        for namespace in reversed(namespaces):
            subprocess.run(["ip", "netns", "del", namespace], check=False)


if __name__ == "__main__":
    main()
