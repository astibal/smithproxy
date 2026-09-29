#!/usr/bin/env python3
"""Validate native and SPQ1 QUIC/H3 observations from one runner scenario."""

import argparse
import collections
import json
import os
import pathlib
import pwd
import shutil
import subprocess
import tempfile


SPQ1_FIELDS = [
    "gre.key",
    "spquic.session_id",
    "spquic.stream_id",
    "spquic.alpn",
    "spquic.fin",
    "spquic.data",
    "sphttp3.stream_id",
    "sphttp3.method",
    "sphttp3.url",
    "sphttp3.status",
]


def tshark_command(capture, fields, display_filter, dissector=None, keylog=None):
    command = ["tshark", "-r", str(capture)]
    if dissector:
        command += ["-X", f"lua_script:{dissector}"]
    if keylog:
        command += ["-o", f"tls.keylog_file:{keylog}"]
    # The fields output defaults to a tab separator, which is unambiguous for
    # the scalar protocol fields selected below.
    command += ["-Y", display_filter, "-T", "fields"]
    for field in fields:
        command += ["-e", field]
    return command


def tshark(capture, fields, display_filter, dissector=None, keylog=None):
    command = tshark_command(capture, fields, display_filter, dissector, keylog)

    # Wireshark deliberately refuses user-supplied Lua while running as root.
    # The runner itself needs root for namespaces and captures, so stage only
    # the immutable decoder inputs and execute tshark as the unprivileged
    # nobody account.  Normal developer runs remain entirely unmodified.
    with tempfile.TemporaryDirectory(prefix="smithproxy-tshark-") as temporary:
        if os.geteuid() == 0:
            account = pwd.getpwnam("nobody")
            staging = pathlib.Path(temporary)
            os.chown(staging, account.pw_uid, account.pw_gid)

            staged_capture = staging / "capture.pcap"
            shutil.copyfile(capture, staged_capture)
            os.chown(staged_capture, account.pw_uid, account.pw_gid)
            staged_dissector = None
            if dissector:
                staged_dissector = staging / "spquic.lua"
                shutil.copyfile(dissector, staged_dissector)
                os.chown(staged_dissector, account.pw_uid, account.pw_gid)
            staged_keylog = None
            if keylog:
                staged_keylog = staging / "quic.keys"
                shutil.copyfile(keylog, staged_keylog)
                os.chown(staged_keylog, account.pw_uid, account.pw_gid)

            command = ["runuser", "-u", "nobody", "--", "env", f"HOME={staging}"] + \
                tshark_command(staged_capture, fields, display_filter,
                               staged_dissector, staged_keylog)

        result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"tshark failed ({result.returncode}): {result.stderr.strip()}")
    rows = []
    for line in result.stdout.splitlines():
        values = line.split("\t")
        values.extend([""] * (len(fields) - len(values)))
        rows.append(dict(zip(fields, values)))
    return rows


def spq1_rows(captures, dissector):
    rows = []
    for capture in captures:
        rows.extend(tshark(capture, SPQ1_FIELDS, "spquic", dissector=dissector))
    return rows


def semantic_summary(rows):
    return {
        "urls": collections.Counter(row["sphttp3.url"] for row in rows
                                    if row["sphttp3.url"]),
        "methods": collections.Counter(row["sphttp3.method"] for row in rows
                                       if row["sphttp3.method"]),
        "statuses": collections.Counter(row["sphttp3.status"] for row in rows
                                        if row["sphttp3.status"]),
    }


def parse_number(value):
    return int(value, 0) if value else None


def field_values(value):
    """Split tshark's comma-joined values for repeated fields in one packet."""
    return [item for item in value.split(",") if item]


def validate_spq1(rows, expected_urls, source, require_gre):
    if not rows:
        raise AssertionError(f"{source}: no SPQ1 packets")
    if {row["spquic.alpn"] for row in rows if row["spquic.alpn"]} != {"h3"}:
        raise AssertionError(f"{source}: missing or unexpected ALPN")

    sessions = {parse_number(row["spquic.session_id"]) for row in rows
                if row["spquic.session_id"]}
    if not sessions or None in sessions:
        raise AssertionError(f"{source}: missing session identity")
    stream_ids = {parse_number(row["sphttp3.stream_id"] or row["spquic.stream_id"])
                  for row in rows
                  if row["sphttp3.stream_id"] or row["spquic.stream_id"]}
    if len(stream_ids) < len(expected_urls):
        raise AssertionError(
            f"{source}: expected at least {len(expected_urls)} streams, got {stream_ids}")

    summary = semantic_summary(rows)
    missing = set(expected_urls) - set(summary["urls"])
    if missing:
        raise AssertionError(f"{source}: missing decoded URLs: {sorted(missing)}")
    if summary["methods"]["GET"] < len(expected_urls):
        raise AssertionError(f"{source}: missing decoded GET methods")
    if summary["statuses"]["200"] < len(expected_urls):
        raise AssertionError(f"{source}: missing decoded 200 responses")
    if not any(row["spquic.data"] for row in rows):
        raise AssertionError(f"{source}: no raw plaintext STREAM data")
    if not any(row["spquic.fin"] in {"1", "True", "true"} for row in rows):
        raise AssertionError(f"{source}: no exported FIN")

    gre_keys = {parse_number(row["gre.key"]) for row in rows if row["gre.key"]}
    if require_gre:
        expected_keys = {session & 0xFFFFFFFF for session in sessions}
        if not gre_keys or not gre_keys.issubset(expected_keys):
            raise AssertionError(
                f"{source}: GRE keys {gre_keys} do not identify sessions {sessions}")
    elif gre_keys:
        raise AssertionError(f"{source}: unexpected GRE encapsulation")
    return sessions, stream_ids, summary


def validate_native(capture, keylog, expected_urls):
    fields = [
        "http3.headers.method",
        "http3.headers.scheme",
        "http3.headers.authority",
        "http3.headers.path",
        "http3.headers.status",
        "quic.stream.stream_id",
    ]
    rows = tshark(capture, fields, "http3", keylog=keylog)
    urls = set()
    methods = collections.Counter()
    statuses = collections.Counter()
    streams = set()
    for row in rows:
        methods.update(field_values(row["http3.headers.method"]))
        statuses.update(field_values(row["http3.headers.status"]))
        streams.update(parse_number(value)
                       for value in field_values(row["quic.stream.stream_id"]))

        schemes = field_values(row["http3.headers.scheme"])
        authorities = field_values(row["http3.headers.authority"])
        paths = field_values(row["http3.headers.path"])
        for scheme, authority, path in zip(schemes, authorities, paths):
            urls.add(f"{scheme}://{authority}{path}")
    missing = set(expected_urls) - urls
    if missing:
        raise AssertionError(f"native capture: missing decrypted URLs: {sorted(missing)}")
    if methods["GET"] < len(expected_urls) or statuses["200"] < len(expected_urls):
        raise AssertionError("native capture: incomplete HTTP/3 request/response headers")
    if len(streams) < len(expected_urls):
        raise AssertionError("native capture: requests did not use independent QUIC streams")
    return {"urls": sorted(urls), "streams": sorted(streams), "packets": len(rows)}


def validate_cli(path, minimum_streams):
    text = path.read_text(errors="replace")
    required = ["QUIC listener[0]", "QUIC|MitM|", "SNI: origin.runner.lab",
                "ALPN: downstream=h3 upstream=h3"]
    missing = [marker for marker in required if marker not in text]
    if missing:
        raise AssertionError(f"CLI snapshot missing: {missing}")
    stream_counts = []
    for line in text.splitlines():
        if "streams:" not in line:
            continue
        try:
            stream_counts.append(int(line.split("streams:", 1)[1].split()[0]))
        except (ValueError, IndexError):
            pass
    if not stream_counts or max(stream_counts) < minimum_streams:
        raise AssertionError(f"CLI did not expose {minimum_streams} live streams")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", type=pathlib.Path, required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--gre", type=pathlib.Path, required=True)
    parser.add_argument("--native", type=pathlib.Path, required=True)
    parser.add_argument("--keylog", type=pathlib.Path, required=True)
    parser.add_argument("--cli", type=pathlib.Path, required=True)
    parser.add_argument("--dissector", type=pathlib.Path, required=True)
    parser.add_argument("--url", action="append", dest="urls", required=True)
    arguments = parser.parse_args()

    local_captures = sorted(arguments.data_dir.glob(arguments.prefix + "*.pcapng"))
    if not local_captures:
        raise AssertionError("no local QUIC PCAPNG capture")
    local_rows = spq1_rows(local_captures, arguments.dissector)
    gre_rows = spq1_rows([arguments.gre], arguments.dissector)
    local_sessions, local_streams, local_summary = validate_spq1(
        local_rows, arguments.urls, "local PCAP", False)
    gre_sessions, gre_streams, gre_summary = validate_spq1(
        gre_rows, arguments.urls, "GRE PCAP", True)
    if local_sessions != gre_sessions or local_streams != gre_streams:
        raise AssertionError("local PCAP and GRE identities differ")
    if local_summary != gre_summary:
        raise AssertionError("local PCAP and GRE semantic records differ")
    validate_cli(arguments.cli, len(arguments.urls))
    native = validate_native(arguments.native, arguments.keylog, arguments.urls)

    print(json.dumps({
        "urls": arguments.urls,
        "sessions": sorted(local_sessions),
        "streams": sorted(local_streams),
        "local_packets": len(local_rows),
        "gre_packets": len(gre_rows),
        "native": native,
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
