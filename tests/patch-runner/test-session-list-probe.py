#!/usr/bin/env python3
"""Regression tests for loaded CLI snapshot framing."""
import importlib.util
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).parent / "harness" / "session-list-probe.py"
SPEC = importlib.util.spec_from_file_location("session_list_probe", MODULE_PATH)
PROBE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROBE)


class PromptRecognitionTest(unittest.TestCase):
    def test_rejects_session_output_ending_in_privilege_marker(self):
        transcript = b"MitM|187|certificate subject: CN=# "
        self.assertFalse(PROBE.is_cli_prompt(transcript, (b"# ", b"> ")))

    def test_accepts_plain_decorated_and_colored_prompts(self):
        prompts = (
            b"rows\r\nsmithproxy(lab)# ",
            b"rows\r\nsmithproxy(lab)<*><!># ",
            b"rows\r\nsmithproxy(lab)(config:/settings/tls)# ",
            (b"rows\r\n\x1b[36msmithpr\x1b[0m\x1b[32m\xe2\x8c\x80"
             b"\x1b[0m\x1b[36mxy\x1b[0m(\x1b[33mlab\x1b[0m)"
             b"\x1b[31m# \x1b[0m"),
        )
        for prompt in prompts:
            with self.subTest(prompt=prompt):
                self.assertTrue(PROBE.is_cli_prompt(prompt, (b"# ", b"> ")))

    def test_login_accepts_initial_privileged_prompt(self):
        sent = []
        def prompt(*markers):
            response = b"\x1b[36msmithproxy(lab)\x1b[0m# "
            self.assertTrue(PROBE.is_cli_prompt(response, markers))
            return response
        PROBE.enter_privileged_mode(prompt, sent.append)
        self.assertEqual(sent, [])

    def test_login_elevates_initial_unprivileged_prompt(self):
        responses = iter((b"smithproxy(lab)> ", b"smithproxy(lab)# "))
        sent = []
        def prompt(*markers):
            response = next(responses)
            self.assertTrue(PROBE.is_cli_prompt(response, markers))
            return response
        PROBE.enter_privileged_mode(prompt, sent.append)
        self.assertEqual(sent, [b"enable\r\n"])

    def test_honors_expected_privilege_marker(self):
        prompt = b"smithproxy(lab)> "
        self.assertTrue(PROBE.is_cli_prompt(prompt, (b"> ",)))
        self.assertFalse(PROBE.is_cli_prompt(prompt, (b"# ",)))


if __name__ == "__main__":
    unittest.main()
