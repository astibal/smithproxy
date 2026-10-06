#!/usr/bin/env python3
import importlib.util
import pathlib
import tempfile
import unittest


REPORTER = pathlib.Path(__file__).with_name("coverage-report.py")
SPEC = importlib.util.spec_from_file_location("coverage_report", REPORTER)
coverage_report = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(coverage_report)


class CoverageReportTests(unittest.TestCase):
    def test_deleted_product_source_is_not_reportable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            deleted = root / "src" / "removed.cpp"
            self.assertFalse(coverage_report.is_product_source(deleted, root))

            deleted.parent.mkdir(parents=True)
            deleted.write_text("int present;\n", encoding="utf-8")
            self.assertTrue(coverage_report.is_product_source(deleted, root))

            deleted.unlink()
            self.assertFalse(coverage_report.is_product_source(deleted, root))


if __name__ == "__main__":
    unittest.main()
