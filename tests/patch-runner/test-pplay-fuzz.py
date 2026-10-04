#!/usr/bin/env python3
import importlib.util
import pathlib
import sys
import types
import unittest


PPLAY_PATH = pathlib.Path(__file__).with_name("vendor") / "pplay.py"
sys.modules["scapy"] = None
SPEC = importlib.util.spec_from_file_location("patch_runner_pplay", PPLAY_PATH)
PPLAY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PPLAY)


class Script:
    def __init__(self):
        self.packets = [b"\x05\x01\x00", b"\x05\x00", b"\x05\x01\x00\xffgarbage"]


class PplayFuzzTests(unittest.TestCase):
    def test_refuzz_is_repeatable_after_server_recreates_script(self):
        repeater = PPLAY.Repeater(None, "")
        repeater.init_fuzz(types.SimpleNamespace(fuzz=["245"], fuzz_magic=["seed-a"]))
        repeater.scripter = Script()
        repeater.scripter_refuzz()
        first = list(repeater.packets)

        repeater.scripter = Script()
        repeater.scripter_refuzz()
        self.assertEqual(first, repeater.packets)
        self.assertNotEqual(Script().packets, repeater.packets)


if __name__ == "__main__":
    unittest.main()
