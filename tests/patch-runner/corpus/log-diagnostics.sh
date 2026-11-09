#!/usr/bin/env bash

pplay_has_failure_diagnostic() {
    # Pplay prints the fixture and working-directory paths before playback.
    # A path containing "timeout" is metadata, not a runtime failure.
    # Keep every other line, including actual timeout and exception reports.
    grep -Ev '^Loading custom script: .* \(pwd=.*\)$' "$1" \
        | grep -Ei 'DIE.AFTER|TIMEOUT|Traceback|AssertionError' > /dev/null
}
