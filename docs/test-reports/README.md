# Test reports

This directory contains concise reports produced by the Smithproxy patch
runner. Reports are grouped by year and named after the UTC test date, tested
commit and profile:

```text
YYYY/YYYY-MM-DD-<commit>-<profile>.md
```

Generate a report only from a clean checkout of the commit being tested:

```sh
tests/patch-runner/publish-report.sh full --remote root@test-host --parallel 3
```

The command writes a report only when the run passes. It does not commit or
push anything. Raw logs and retained lab artifacts stay outside the repository.
Concrete test-host names are intentionally omitted from published reports.
