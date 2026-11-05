#!/usr/bin/env python3
"""Verify that lifecycle XFAIL rules cannot hide a different failure."""
import runpy
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
module = runpy.run_path(str(HERE / "test-proxy-nightmare-lifecycle.py"))
classify = module["classify_functional"]
load = module["expected_failures"]

rule = load()["tls_client_hello_fin"]
signature = rule["log_contains"]
assert classify(0, "", None) == "PASS"
assert classify(1, "ordinary failure", None) == "FAIL"
assert classify(1, signature, rule) == "XFAIL"
assert classify(1, "a different timeout", rule) == "FAIL"
assert classify(0, "", rule) == "XPASS"
print("PASS: lifecycle XFAIL requires the exact signature and XPASS stops the gate")
