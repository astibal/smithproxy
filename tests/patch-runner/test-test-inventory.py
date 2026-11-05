#!/usr/bin/env python3
import json
import subprocess
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent


with tempfile.TemporaryDirectory() as tmp:
    report = Path(tmp)
    (report / "sections").mkdir()
    (report / "native").mkdir()
    (report / "sections.tsv").write_text(
        "section\ttarget\tresult\trc\treason\treport\n"
        "native\tlocal\tPASS\t0\tok\t-\n"
        "smoke\tremote-1\tPASS\t0\tok\t-\n"
        "lifecycle\tremote-1\tPASS\t0\tone xfail\t-\n"
    )
    (report / "native" / "junit.xml").write_text(
        '<testsuite><testcase name="unit.first" time="0.1"/>'
        '<testcase name="unit.second" time="0.2"><skipped/></testcase></testsuite>'
    )
    (report / "sections" / "smoke.log").write_text(
        "PASS4 HTTP/1 GET\nPASS6 HTTP/1 GET\n"
        "PASS cleanup: namespaces removed\nRESULT: PASS\n"
    )
    (report / "sections" / "lifecycle.log").write_text(
        "close_after_fin PASS\ntls_client_hello_fin XFAIL\n"
    )
    subprocess.run(["python3", str(HERE / "test-inventory.py"), str(report)], check=True)
    data = json.loads((report / "test-inventory.json").read_text())["sections"]
    assert [item["section"] for item in data] == ["native", "smoke", "lifecycle"]
    assert [case["name"] for case in data[0]["cases"]] == ["unit.first", "unit.second"]
    assert data[0]["cases"][1]["result"] == "SKIP"
    assert data[1]["cases"][0] == {
        "name": "HTTP/1 GET", "family": "IPv4+IPv6", "result": "PASS", "detail": ""
    }
    assert all(case["name"] != "RESULT:" for item in data for case in item["cases"])
    assert data[2]["cases"][1]["result"] == "XFAIL"
    markdown = (report / "test-inventory.md").read_text()
    assert markdown.index("### native") < markdown.index("### sanity") < markdown.index("### lifecycle")

print("PASS: complete test inventory is stable, exhaustive and family-aware")
