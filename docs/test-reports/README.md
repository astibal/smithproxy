# Test reports

Since October 2026, Smithproxy uses these reports as the durable record of its
strict testing policy. A report identifies the exact tested commit and records
the validation profile, section results, selected metrics and reproduction
command. It is evidence for that commit and profile, not a blanket guarantee for
other builds or environments.

This directory contains concise reports produced by the Smithproxy patch
runner. Reports are grouped by year and named after the UTC test date, tested
commit and profile:

```text
YYYY/YYYY-MM-DDTHHMMSSZ-<branch>-<commit>-<profile>.md
```

Generate a report only from a clean checkout of the commit being tested:

```sh
tests/patch-runner/publish-report.sh full --remote root@test-host --parallel 3
```

The command writes a report only when the run passes from a clean checkout. It
then verifies that HEAD and the branch did not change during the run, commits
only the report metadata and pushes `HEAD` explicitly to the same branch name.
Raw logs, the complete test inventory and retained lab artifacts stay outside
the repository. Concrete test-host names are intentionally omitted.

The report commit is selective. The following push necessarily transfers the
complete unpushed history of the tested branch; Git cannot push only one commit
while omitting its ancestors.

Published validation must run through `publish-report.sh`; invoking
`test-patch.sh` directly is a local diagnostic run and does not satisfy this
archival requirement. Always check the printed branch before treating the
published report as evidence for a change.

Reports are retained so later regression investigations can reconstruct when a
revision was tested, what was included and which measurements were observed.
