#!/usr/bin/env python3
"""Render a concrete mem-constrained config from the common config."""
import argparse
import pathlib
import re


PROFILES = {
    "socks": {
        "accept_tproxy": "FALSE",
        "accept_redirect": "FALSE",
        "accept_socks": "TRUE",
        "plaintext_workers": "-1",
        "ssl_workers": "-1",
        "udp_workers": "-1",
        "dtls_workers": "-1",
        "socks_workers": "1",
    },
    "tproxy": {
        "accept_tproxy": "TRUE",
        "accept_redirect": "FALSE",
        "accept_socks": "FALSE",
        "plaintext_workers": "1",
        "ssl_workers": "-1",
        "udp_workers": "-1",
        "dtls_workers": "-1",
        "socks_workers": "-1",
    },
}


def replace_setting(text: str, key: str, value: str) -> str:
    pattern = rf"(?m)^(\s*{re.escape(key)}\s*=\s*)[^;]+(;)"
    rendered, count = re.subn(pattern, rf"\g<1>{value}\2", text, count=1)
    if count != 1:
        raise ValueError(f"expected exactly one setting: {key}")
    return rendered


parser = argparse.ArgumentParser()
parser.add_argument("profile", choices=sorted(PROFILES))
parser.add_argument("source", type=pathlib.Path)
parser.add_argument("destination", type=pathlib.Path)
args = parser.parse_args()

text = args.source.read_text()
for setting, value in PROFILES[args.profile].items():
    text = replace_setting(text, setting, value)
args.destination.parent.mkdir(parents=True, exist_ok=True)
args.destination.write_text(text)
