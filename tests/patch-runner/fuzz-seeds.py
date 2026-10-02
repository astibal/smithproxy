#!/usr/bin/env python3
"""Select a bounded, reproducible set from the successful fuzz seed pool."""

import argparse
import datetime as dt
import hashlib
from pathlib import Path


def read_seeds(path: Path):
    rows = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw or raw.startswith("#"):
            continue
        fields = raw.split("\t")
        if len(fields) != 4:
            raise SystemExit(f"invalid seed row in {path}: {raw!r}")
        date_text, seed, generator, status = fields
        if status not in {"covered", "regression"}:
            raise SystemExit(f"invalid seed status {status!r} in {path}")
        rows.append((dt.date.fromisoformat(date_text), seed, generator, status))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("registry", type=Path)
    parser.add_argument("area")
    parser.add_argument("--recent", type=int, default=4)
    parser.add_argument("--archive", type=int, default=4)
    parser.add_argument("--rotation-days", type=int, default=7)
    parser.add_argument("--min-age-days", type=int, default=1)
    parser.add_argument(
        "--today", type=dt.date.fromisoformat,
        default=dt.datetime.now(dt.timezone.utc).date(),
    )
    args = parser.parse_args()
    if min(args.recent, args.archive, args.rotation_days, args.min_age_days) < 0 or args.rotation_days == 0:
        parser.error("counts and ages must be non-negative; rotation-days must be positive")

    rows = read_seeds(args.registry)
    eligible = [row for row in rows if (args.today - row[0]).days >= args.min_age_days]
    pinned = [row for row in rows if row[3] == "regression"]
    selected = {row[1]: row for row in pinned}

    recent = sorted(
        (row for row in eligible if row[1] not in selected),
        key=lambda row: (row[0], row[1]), reverse=True,
    )
    for row in recent[: args.recent]:
        selected.setdefault(row[1], row)

    epoch = args.today.toordinal() // args.rotation_days
    archive = [row for row in eligible if row[1] not in selected]
    archive.sort(key=lambda row: hashlib.sha256(
        f"{epoch}:{args.area}:{row[1]}:{row[2]}".encode()
    ).digest())
    for row in archive[: args.archive]:
        selected[row[1]] = row

    if not selected:
        raise SystemExit("no fuzz seeds selected")
    print(",".join(sorted(selected)))


if __name__ == "__main__":
    main()
