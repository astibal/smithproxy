#!/usr/bin/env python3
"""Create deterministic source-line coverage reports from GCC gcov data."""

from __future__ import annotations

import argparse
import gzip
import html
import json
import pathlib
import shutil
import subprocess
import tempfile


def is_product_source(path: pathlib.Path, root: pathlib.Path) -> bool:
    try:
        relative = path.resolve().relative_to(root)
    except ValueError:
        return False
    if relative.suffix not in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".tpp"}:
        return False
    parts = relative.parts
    if not parts or parts[0] not in {"src", "socle"}:
        return False
    if parts[:2] == ("src", "ext"):
        return False
    return not any(part in {"tests", "testbed", "fuzz", "third_party"} for part in parts)


def load_gcov(build: pathlib.Path, root: pathlib.Path) -> dict[pathlib.Path, dict[int, int]]:
    coverage: dict[pathlib.Path, dict[int, int]] = {}
    # Notes files define the executable-line universe. Data files only exist
    # after an object has run; using them as the inventory silently drops
    # completely unexecuted objects and inflates the global percentage.
    notes = sorted(build.rglob("*.gcno"))
    objects = [note.with_suffix(".gcda") if note.with_suffix(".gcda").exists() else note
               for note in notes]
    if not objects:
        raise RuntimeError(f"no gcno files found below {build}")
    with tempfile.TemporaryDirectory(prefix="smithproxy-gcov-") as temporary:
        work = pathlib.Path(temporary)
        for index, data_file in enumerate(objects):
            object_work = work / str(index)
            object_work.mkdir()
            completed = subprocess.run(
                ["gcov", "--json-format", "--branch-counts", str(data_file)],
                cwd=object_work,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            if completed.returncode != 0:
                raise RuntimeError(f"gcov failed for {data_file}: {completed.stderr.strip()}")
            for report in object_work.glob("*.gcov.json.gz"):
                with gzip.open(report, "rt", encoding="utf-8") as source:
                    payload = json.load(source)
                current_directory = pathlib.Path(payload.get("current_working_directory", root))
                for file_data in payload.get("files", []):
                    source_path = pathlib.Path(file_data["file"])
                    if not source_path.is_absolute():
                        source_path = current_directory / source_path
                    source_path = source_path.resolve()
                    if not is_product_source(source_path, root):
                        continue
                    lines = coverage.setdefault(source_path, {})
                    for line in file_data.get("lines", []):
                        number = int(line["line_number"])
                        lines[number] = lines.get(number, 0) + int(line.get("count", 0))
    return coverage


def percentage(covered: int, total: int) -> float:
    return 100.0 * covered / total if total else 100.0


def write_reports(coverage: dict[pathlib.Path, dict[int, int]], root: pathlib.Path,
                  output: pathlib.Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    file_rows = []
    total_lines = total_covered = 0
    detail_dir = output / "files"
    if detail_dir.exists():
        shutil.rmtree(detail_dir)
    detail_dir.mkdir(exist_ok=True)

    for source_path in sorted(coverage):
        line_counts = coverage[source_path]
        executable = len(line_counts)
        covered = sum(count > 0 for count in line_counts.values())
        total_lines += executable
        total_covered += covered
        relative = source_path.relative_to(root).as_posix()
        detail_name = relative.replace("/", "__") + ".html"
        file_rows.append({
            "file": relative,
            "covered": covered,
            "lines": executable,
            "percent": percentage(covered, executable),
            "detail": f"files/{detail_name}",
        })
        source_lines = source_path.read_text(encoding="utf-8", errors="replace").splitlines()
        rendered = []
        for number, text in enumerate(source_lines, 1):
            count = line_counts.get(number)
            css = "neutral" if count is None else ("hit" if count > 0 else "miss")
            count_text = "" if count is None else str(count)
            rendered.append(
                f'<tr class="{css}"><td>{number}</td><td>{count_text}</td>'
                f'<td><pre>{html.escape(text)}</pre></td></tr>'
            )
        (detail_dir / detail_name).write_text(
            "<!doctype html><meta charset='utf-8'><style>"
            "body{font-family:sans-serif}table{border-collapse:collapse;width:100%}"
            "td{vertical-align:top;padding:0 6px}.hit{background:#e6ffed}.miss{background:#ffeef0}"
            ".neutral{color:#666}pre{margin:0;white-space:pre-wrap}</style>"
            f"<h1>{html.escape(relative)}</h1><table>{''.join(rendered)}</table>",
            encoding="utf-8",
        )

    summary = {
        "covered_lines": total_covered,
        "executable_lines": total_lines,
        "line_percent": percentage(total_covered, total_lines),
        "files": file_rows,
    }
    (output / "coverage.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (output / "summary.txt").write_text(
        f"line coverage: {total_covered}/{total_lines} "
        f"({summary['line_percent']:.2f}%)\nfiles: {len(file_rows)}\n",
        encoding="utf-8",
    )
    rows = "".join(
        f"<tr><td><a href='{html.escape(row['detail'])}'>{html.escape(row['file'])}</a></td>"
        f"<td>{row['covered']}</td><td>{row['lines']}</td><td>{row['percent']:.2f}%</td></tr>"
        for row in file_rows
    )
    (output / "index.html").write_text(
        "<!doctype html><meta charset='utf-8'><style>"
        "body{font-family:sans-serif;max-width:1200px;margin:auto}"
        "table{border-collapse:collapse;width:100%}th,td{padding:5px;border-bottom:1px solid #ddd}"
        "th{text-align:left}</style><h1>Smithproxy line coverage</h1>"
        f"<p>{total_covered}/{total_lines} executable lines "
        f"({summary['line_percent']:.2f}%)</p>"
        "<table><tr><th>File</th><th>Covered</th><th>Lines</th><th>Coverage</th></tr>"
        f"{rows}</table>",
        encoding="utf-8",
    )
    print((output / "summary.txt").read_text(encoding="utf-8"), end="")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=pathlib.Path, required=True)
    parser.add_argument("--build-dir", type=pathlib.Path, required=True)
    parser.add_argument("--output-dir", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if not shutil.which("gcov"):
        parser.error("gcov is required")
    root = args.source_root.resolve()
    write_reports(load_gcov(args.build_dir.resolve(), root), root, args.output_dir.resolve())


if __name__ == "__main__":
    main()
