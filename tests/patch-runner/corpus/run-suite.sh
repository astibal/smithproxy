#!/usr/bin/env bash
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
PPLAY_PY=${PPLAY_PY:-}
CATEGORY=${1:-all}
MODE=${MODE:-loopback}
RESULTS=${RESULTS:-$HERE/results}
PORT=${PORT:-18080}
IP_FAMILY=${IP_FAMILY:-4}
MATCH=${MATCH:-*}
EXCLUDE=${EXCLUDE:-}
FUZZ_LEVEL=${FUZZ_LEVEL:-}
FUZZ_MAGIC=${FUZZ_MAGIC:-smithproxy-corpus}
SCATTER=${SCATTER:-0}
SOURCE_PORT=${SOURCE_PORT:-}
EXPECTED_FAILURES_FILE=${EXPECTED_FAILURES_FILE:-$HERE/expected-failures.txt}
export PYTHONPATH="$HERE${PYTHONPATH:+:$PYTHONPATH}"

[[ -n $PPLAY_PY && -f $PPLAY_PY ]] || {
    echo 'Set PPLAY_PY=/absolute/path/to/pplay.py' >&2
    exit 2
}
[[ $CATEGORY == all || $CATEGORY == regular || $CATEGORY == edge || $CATEGORY == insanity ]] || {
    echo 'Usage: run-suite.sh [all|regular|edge|insanity]' >&2
    exit 2
}
[[ $IP_FAMILY == 4 || $IP_FAMILY == 6 ]] || { echo 'IP_FAMILY must be 4 or 6' >&2; exit 2; }

case "$MODE" in
    loopback)
        if [[ $IP_FAMILY == 6 ]]; then
            SERVER_BIND=::1; CLIENT_TARGET=::1
        else
            SERVER_BIND=127.0.0.1; CLIENT_TARGET=127.0.0.1
        fi
        SERVER_EXEC=()
        CLIENT_EXEC=()
        ;;
    runner)
        if [[ $IP_FAMILY == 6 ]]; then
            SERVER_BIND=${SERVER_BIND:-fd00:20::2}
            CLIENT_TARGET=${CLIENT_TARGET:-fd00:20::2}
        else
            SERVER_BIND=${SERVER_BIND:-198.18.20.2}
            CLIENT_TARGET=${CLIENT_TARGET:-198.18.20.2}
        fi
        SERVER_NS=${SERVER_NS:-sxr-origin}
        CLIENT_NS=${CLIENT_NS:-sxr-client}
        SERVER_EXEC=(ip netns exec "$SERVER_NS")
        CLIENT_EXEC=(ip netns exec "$CLIENT_NS")
        ;;
    *)
        echo 'MODE must be loopback or runner' >&2
        exit 2
        ;;
esac
if [[ $IP_FAMILY == 6 ]]; then
    SERVER_ENDPOINT="[$SERVER_BIND]:$PORT"
    CLIENT_ENDPOINT="[$CLIENT_TARGET]:$PORT"
else
    SERVER_ENDPOINT="$SERVER_BIND:$PORT"
    CLIENT_ENDPOINT="$CLIENT_TARGET:$PORT"
fi

mkdir -p "$RESULTS"
PPLAY_SERVER_PID=
cleanup_server() {
    [[ -z $PPLAY_SERVER_PID ]] || kill "$PPLAY_SERVER_PID" 2>/dev/null || true
    [[ -z $PPLAY_SERVER_PID ]] || wait "$PPLAY_SERVER_PID" 2>/dev/null || true
    PPLAY_SERVER_PID=
}
trap cleanup_server EXIT
trap 'cleanup_server; exit 130' INT TERM

matches_glob_list() {
    local candidate=$1 glob_list=$2 pattern
    local -a patterns=()
    [[ -n $glob_list ]] || return 1
    IFS=, read -r -a patterns <<< "$glob_list"
    for pattern in "${patterns[@]}"; do
        [[ -n $pattern && $candidate == $pattern ]] && return 0
    done
    return 1
}

is_selected() {
    local candidate=$1
    matches_glob_list "$candidate" "$MATCH" && ! matches_glob_list "$candidate" "$EXCLUDE"
}

mapfile -t CASES < <(
    if [[ $CATEGORY == all ]]; then
        find "$HERE/regular" "$HERE/edge" "$HERE/insanity" -maxdepth 1 -type f -name '*.py' -print
    else
        find "$HERE/$CATEGORY" -maxdepth 1 -type f -name '*.py' -print
    fi | while IFS= read -r fixture; do
        if is_selected "$(basename "$fixture" .py)"; then
            printf '%s\n' "$fixture"
        fi
    done | sort

    for generated_category in regular edge insanity; do
        [[ $CATEGORY == all || $CATEGORY == "$generated_category" ]] || continue
        case "$generated_category" in
            regular) generated_last=133 ;;
            edge|insanity) generated_last=132 ;;
        esac
        for generated_index in $(seq 0 "$generated_last"); do
            generated_name=$(printf 'generated_%03d' "$generated_index")
            (( generated_index % 10 < 7 )) || generated_name="udp_$generated_name"
            is_selected "$generated_name" || continue
            printf 'virtual|%s|%03d|%s\n' "$generated_category" "$generated_index" "$generated_name"
        done

        case "$generated_category" in
            regular) h2_first=200; h2_last=239 ;;
            edge) h2_first=240; h2_last=269 ;;
            insanity) h2_first=270; h2_last=299 ;;
        esac
        for generated_index in $(seq "$h2_first" "$h2_last"); do
            generated_name=$(printf 'h2_generated_%03d' "$((generated_index - 200))")
            is_selected "$generated_name" || continue
            printf 'virtual|%s|%03d|%s\n' "$generated_category" "$generated_index" "$generated_name"
        done

        case "$generated_category" in
            regular) capture_first=0; capture_last=11 ;;
            edge) capture_first=12; capture_last=21 ;;
            insanity) capture_first=22; capture_last=29 ;;
        esac
        for capture_index in $(seq "$capture_first" "$capture_last"); do
            if ((capture_index < 22)); then
                capture_name=$(printf 'capture_tcp_%02d' "$capture_index")
            else
                capture_name=$(printf 'capture_udp_%02d' "$capture_index")
            fi
            is_selected "$capture_name" || continue
            printf 'capture|%s|%02d|%s\n' "$generated_category" "$capture_index" "$capture_name"
        done
    done
)
(( ${#CASES[@]} > 0 )) || {
    echo "No cases matched category=$CATEGORY match=$MATCH exclude=${EXCLUDE:-<none>}" >&2
    exit 2
}

passed=0
flaky=0
failed=0
xfailed=0
xpassed=0
for fixture in "${CASES[@]}"; do
    CASE_ENV=(env)
    if [[ $fixture == capture\|* ]]; then
        IFS='|' read -r _ category capture_index name <<< "$fixture"
        fixture="$HERE/_capture_matrix_case.py"
        CASE_ENV+=("PPLAY_CAPTURE_INDEX=$capture_index")
    elif [[ $fixture == virtual\|* ]]; then
        IFS='|' read -r _ category generated_index name <<< "$fixture"
        fixture="$HERE/_generated_case.py"
        CASE_ENV+=("PPLAY_GENERATED_CATEGORY=$category" "PPLAY_GENERATED_INDEX=$generated_index")
    else
        category=$(basename "$(dirname "$fixture")")
        name=$(basename "$fixture" .py)
    fi
    out="$RESULTS/$category/$name"
    mkdir -p "$out"
    PROTO_ARGS=()
    SS_ARGS=(-ltnH "sport = :$PORT")
    max_attempts=1
    if [[ $name == udp_* || $name == capture_udp_* ]]; then
        PROTO_ARGS=(--udp)
        SS_ARGS=(-lunH "sport = :$PORT")
        max_attempts=3
    fi

    MUTATION_ARGS=()
    if [[ -n $FUZZ_LEVEL ]]; then
        MUTATION_ARGS+=(--fuzz "$FUZZ_LEVEL" --fuzz-magic "$FUZZ_MAGIC:$category:$name")
    fi
    if [[ $SCATTER == 1 ]]; then
        MUTATION_ARGS+=(--scatter --scatter-magic "$FUZZ_MAGIC:$category:$name")
    fi

    CLIENT_SOURCE_ARGS=()
    [[ -z $SOURCE_PORT ]] || CLIENT_SOURCE_ARGS=(--sport "$SOURCE_PORT")

    case_passed=false
    passed_attempt=0
    for case_attempt in $(seq 1 "$max_attempts"); do
        server_log="$out/server.log"
        client_log="$out/client.log"
        if ((case_attempt > 1)); then
            server_log="$out/server.retry-$case_attempt.log"
            client_log="$out/client.retry-$case_attempt.log"
        fi

        "${CASE_ENV[@]}" "${SERVER_EXEC[@]}" python3 -u "$PPLAY_PY" --script "$fixture" \
            --server "$SERVER_ENDPOINT" --auto 0.01 --nostdin --exitoneot \
            --exitondiff --die-after 15 --nohex --nocolor "${PROTO_ARGS[@]}" "${MUTATION_ARGS[@]}" > "$server_log" 2>&1 &
        PPLAY_SERVER_PID=$!

        ready=false
        for ready_attempt in $(seq 1 100); do
            if "${SERVER_EXEC[@]}" ss "${SS_ARGS[@]}" | grep -q .; then
                ready=true
                break
            fi
            kill -0 "$PPLAY_SERVER_PID" 2>/dev/null || break
            sleep 0.05
        done

        client_rc=1
        server_rc=1
        if $ready; then
            set +e
            "${CASE_ENV[@]}" "${CLIENT_EXEC[@]}" python3 -u "$PPLAY_PY" --script "$fixture" \
                --client "$CLIENT_ENDPOINT" --auto 0.01 --nostdin --exitoneot \
                --exitondiff --die-after 15 --nohex --nocolor "${PROTO_ARGS[@]}" "${MUTATION_ARGS[@]}" \
                "${CLIENT_SOURCE_ARGS[@]}" > "$client_log" 2>&1
            client_rc=$?
            wait "$PPLAY_SERVER_PID"
            server_rc=$?
            set -e
            PPLAY_SERVER_PID=
        else
            cleanup_server
        fi

        if $ready && [[ $client_rc == 0 && $server_rc == 0 ]] \
            && grep -q 'END OF TRANSMISSION' "$client_log" \
            && grep -q 'END OF TRANSMISSION' "$server_log" \
            && ! grep -q '^# !!!.*DIFFERENT DATA' "$client_log" \
            && ! grep -q '^# !!!.*DIFFERENT DATA' "$server_log"; then
            case_passed=true
            passed_attempt=$case_attempt
            break
        fi
    done

    expected=false
    if [[ -r $EXPECTED_FAILURES_FILE ]] \
        && grep -Fqx "$category/$name" "$EXPECTED_FAILURES_FILE"; then
        expected=true
    fi

    if $case_passed; then
        if $expected; then
            printf '%-10s %-34s %s\n' "$category" "$name" "XPASS$IP_FAMILY"
            ((xpassed += 1))
            ((passed += 1))
        elif ((passed_attempt > 1)); then
            printf '%-10s %-34s %s\n' "$category" "$name" "FLAKY_PASS$IP_FAMILY"
            ((flaky += 1))
        else
            printf '%-10s %-34s %s\n' "$category" "$name" "PASS$IP_FAMILY"
            ((passed += 1))
        fi
    else
        if $expected; then
            printf '%-10s %-34s %s\n' "$category" "$name" "XFAIL$IP_FAMILY"
            ((xfailed += 1))
        else
            printf '%-10s %-34s %s\n' "$category" "$name" "FAIL$IP_FAMILY"
            ((failed += 1))
        fi
    fi

    if [[ -n ${SMITHPROXY_PID_FILE:-} ]]; then
        proxy_pid=
        [[ ! -r $SMITHPROXY_PID_FILE ]] || read -r proxy_pid < "$SMITHPROXY_PID_FILE"
        if [[ -z $proxy_pid ]] || ! kill -0 "$proxy_pid" 2>/dev/null; then
            echo "ABORT: Smithproxy exited while running $category/$name" >&2
            echo "passed=$passed flaky=$flaky failed=$failed xfailed=$xfailed xpassed=$xpassed results=$RESULTS"
            exit 3
        fi
    fi
done

echo "family=IPv$IP_FAMILY passed=$passed flaky=$flaky failed=$failed xfailed=$xfailed xpassed=$xpassed results=$RESULTS"
[[ $failed == 0 ]]
