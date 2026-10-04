#!/usr/bin/env python3
import pathlib
import subprocess
import sys
import tempfile
import unittest


SELECTOR = pathlib.Path(__file__).with_name("fuzz-seeds.py")


class FuzzSeedSelectionTests(unittest.TestCase):
    def test_selection_is_bounded_but_keeps_regressions(self):
        with tempfile.TemporaryDirectory() as temporary:
            registry = pathlib.Path(temporary) / "covered-seeds"
            registry.write_text(
                "# date\tseed\tgenerator\tstatus\n"
                "2026-01-01\tpinned\tv1\tregression\n"
                "2026-09-01\told-a\tv1\tcovered\n"
                "2026-09-02\told-b\tv1\tcovered\n"
                "2026-09-29\trecent-a\tv1\tcovered\n"
                "2026-09-30\trecent-b\tv1\tcovered\n",
                encoding="utf-8",
            )
            command = [
                sys.executable, str(SELECTOR), str(registry), "h2", "--today", "2026-10-02",
                "--recent", "1", "--archive", "1", "--rotation-days", "7",
                "--min-age-days", "1",
            ]
            first = subprocess.check_output(command, text=True).strip().split(",")
            second = subprocess.check_output(command, text=True).strip().split(",")
            self.assertEqual(first, second)
            self.assertEqual(3, len(first))
            self.assertIn("pinned", first)
            self.assertIn("recent-b", first)


if __name__ == "__main__":
    unittest.main()
