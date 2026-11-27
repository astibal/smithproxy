#!/usr/bin/env python3
"""Run inside a disposable network namespace with a policy helper argument."""
import json
import subprocess
import sys

HELPER = sys.argv[1]


def ip(*args):
    return subprocess.check_output(['ip', *args], text=True)


def ensure(*args, succeeds=True):
    result = subprocess.run([sys.executable, HELPER, *args], capture_output=True, text=True)
    assert (result.returncode == 0) == succeeds, result.stderr


ip('rule', 'add', 'pref', '999', 'fwmark', '1/1', 'table', '100')
ensure('4', '29100', '1', '1', '100')
ensure('4', '29100', '1', '1', '100')
rules = json.loads(ip('-j', 'rule'))
assert len([rule for rule in rules if rule['priority'] == 29100]) == 1
assert not any(rule['priority'] == 999 for rule in rules)

ensure('4', '29800', '0x20000', '0xffff0000', '10002')
ensure('4', '29800', '0x1020000', '0xffff0000', '10258')
ensure('4', '29800', '0x20000', '0xffff0000', '20002', succeeds=False)
ip('rule', 'add', 'pref', '29001', 'table', '123')
before = ip('-j', 'rule')
ensure('4', '29001', '1', '1', '100', succeeds=False)
assert before == ip('-j', 'rule')

ensure('6', '29100', '1', '1', '100')
ensure('6', '29100', '1', '1', '100')
print('PASS: migration, idempotence, disjoint marks, collision protection and IPv6')
