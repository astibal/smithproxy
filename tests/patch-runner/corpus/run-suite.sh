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
ALLOW_EMPTY=${ALLOW_EMPTY:-0}
LIST_ONLY=${LIST_ONLY:-0}
FUZZ_LEVEL=${FUZZ_LEVEL:-}
FUZZ_MAGIC=${FUZZ_MAGIC:-smithproxy-corpus}
FUZZ_SEEDS=${FUZZ_SEEDS:-}
FUZZ_AREA=${FUZZ_AREA:-}
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

if [[ -n $FUZZ_SEEDS ]]; then
    IFS=, read -r -a fuzz_seed_list <<< "$FUZZ_SEEDS"
    ((${#fuzz_seed_list[@]} > 0)) || { echo 'FUZZ_SEEDS is empty' >&2; exit 2; }
    fuzz_seed_rc=0
    for fuzz_seed in "${fuzz_seed_list[@]}"; do
        [[ $fuzz_seed =~ ^[A-Za-z0-9._-]+$ ]] || {
            echo "Invalid fuzz seed: $fuzz_seed" >&2
            exit 2
        }
        echo "FUZZ seed=$fuzz_seed family=IPv$IP_FAMILY"
        env FUZZ_SEEDS= FUZZ_MAGIC="$fuzz_seed" \
            RESULTS="$RESULTS/seed-$fuzz_seed" "$0" "$CATEGORY" || fuzz_seed_rc=1
    done
    exit "$fuzz_seed_rc"
fi

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
    local candidate=$1 category=${2:-} generated_index=${3:-}
    matches_glob_list "$candidate" "$MATCH" && ! matches_glob_list "$candidate" "$EXCLUDE" || return 1
    [[ -z $FUZZ_AREA ]] && return 0
    case_fuzz_area "$candidate" "$category" "$generated_index"
    [[ $CASE_FUZZ_AREA == "$FUZZ_AREA" ]]
}

case_fuzz_area() {
    local name=$1 category=${2:-} generated_index=${3:-} family variant
    if [[ -n $generated_index ]]; then
        # Virtual fixture records store the index zero-padded.  Bash treats a
        # leading zero as octal in arithmetic contexts, so 008/009 must be
        # normalized explicitly as decimal before modulo/division.
        generated_index=$((10#$generated_index))
        if ((generated_index >= 200)); then CASE_FUZZ_AREA=h2; return; fi
        family=$((generated_index % 10))
        variant=$((generated_index / 100))
        case "$category:$variant:$family" in
            regular:0:0|regular:0:1|regular:0:2|regular:1:0|regular:1:1|regular:1:2) CASE_FUZZ_AREA=h1 ;;
            regular:*:3) CASE_FUZZ_AREA=h2 ;;
            regular:0:4) CASE_FUZZ_AREA=redis ;;
            regular:0:5) CASE_FUZZ_AREA=smtp ;;
            regular:*:6) CASE_FUZZ_AREA=raw ;;
            regular:*:7) CASE_FUZZ_AREA=dns ;;
            regular:0:8) CASE_FUZZ_AREA=syslog ;;
            regular:1:4) CASE_FUZZ_AREA=websocket ;;
            regular:1:5) CASE_FUZZ_AREA=imap ;;
            regular:1:8) CASE_FUZZ_AREA=ntp ;;
            regular:1:9) CASE_FUZZ_AREA=stun ;;
            regular:0:9) CASE_FUZZ_AREA=raw ;;
            edge:0:0|edge:0:1|edge:0:2|edge:1:0|edge:1:1|edge:1:2|edge:1:5) CASE_FUZZ_AREA=h1 ;;
            edge:0:3|edge:1:3|edge:1:4) CASE_FUZZ_AREA=h2 ;;
            edge:0:4) CASE_FUZZ_AREA=redis ;;
            edge:0:5) CASE_FUZZ_AREA=smtp ;;
            edge:*:6) CASE_FUZZ_AREA=raw ;;
            edge:*:7) CASE_FUZZ_AREA=dns ;;
            edge:*:8) CASE_FUZZ_AREA=syslog ;;
            edge:*:9) CASE_FUZZ_AREA=quic ;;
            insanity:0:0|insanity:0:1|insanity:0:2|insanity:1:0|insanity:1:1|insanity:1:2) CASE_FUZZ_AREA=h1 ;;
            insanity:0:3|insanity:1:3|insanity:1:4) CASE_FUZZ_AREA=h2 ;;
            insanity:0:4|insanity:1:6) CASE_FUZZ_AREA=redis ;;
            insanity:*:5) CASE_FUZZ_AREA=tls ;;
            insanity:0:6) CASE_FUZZ_AREA=socks5 ;;
            insanity:*:7) CASE_FUZZ_AREA=dns ;;
            insanity:0:8) CASE_FUZZ_AREA=mqtt ;;
            insanity:1:8) CASE_FUZZ_AREA=stun ;;
            insanity:*:9) CASE_FUZZ_AREA=quic ;;
            *) CASE_FUZZ_AREA=raw ;;
        esac
        return
    fi
    case "$name" in
        *websocket*) CASE_FUZZ_AREA=websocket ;;
        http1_*|http09) CASE_FUZZ_AREA=h1 ;;
        http2_*|h2_generated_*) CASE_FUZZ_AREA=h2 ;;
        tls_*) CASE_FUZZ_AREA=tls ;;
        socks5_*) CASE_FUZZ_AREA=socks5 ;;
        udp_dns_*|dns_tcp_*|dns_over_tcp) CASE_FUZZ_AREA=dns ;;
        udp_quic_*) CASE_FUZZ_AREA=quic ;;
        redis_*) CASE_FUZZ_AREA=redis ;;
        mqtt_*) CASE_FUZZ_AREA=mqtt ;;
        smtp_*) CASE_FUZZ_AREA=smtp ;;
        imap_*) CASE_FUZZ_AREA=imap ;;
        pop3_*) CASE_FUZZ_AREA=pop3 ;;
        ftp_*) CASE_FUZZ_AREA=ftp ;;
        ssh_*) CASE_FUZZ_AREA=ssh ;;
        memcached_*) CASE_FUZZ_AREA=memcached ;;
        postgresql_*) CASE_FUZZ_AREA=postgresql ;;
        mysql_*) CASE_FUZZ_AREA=mysql ;;
        amqp_*) CASE_FUZZ_AREA=amqp ;;
        telnet_*) CASE_FUZZ_AREA=telnet ;;
        udp_ntp*) CASE_FUZZ_AREA=ntp ;;
        udp_syslog*) CASE_FUZZ_AREA=syslog ;;
        udp_stun*) CASE_FUZZ_AREA=stun ;;
        udp_tftp*) CASE_FUZZ_AREA=tftp ;;
        udp_snmp*) CASE_FUZZ_AREA=snmp ;;
        *) CASE_FUZZ_AREA=raw ;;
    esac
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
            is_selected "$generated_name" "$generated_category" "$generated_index" || continue
            printf 'virtual|%s|%03d|%s\n' "$generated_category" "$generated_index" "$generated_name"
        done

        case "$generated_category" in
            regular) h2_first=200; h2_last=239 ;;
            edge) h2_first=240; h2_last=269 ;;
            insanity) h2_first=270; h2_last=299 ;;
        esac
        for generated_index in $(seq "$h2_first" "$h2_last"); do
            generated_name=$(printf 'h2_generated_%03d' "$((generated_index - 200))")
            is_selected "$generated_name" "$generated_category" "$generated_index" || continue
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
if (( ${#CASES[@]} == 0 )); then
    if [[ $ALLOW_EMPTY == 1 ]]; then
        echo "family=IPv$IP_FAMILY passed=0 flaky=0 failed=0 xfailed=0 xpassed=0 selected=0 results=$RESULTS"
        exit 0
    fi
    echo "No cases matched category=$CATEGORY match=$MATCH exclude=${EXCLUDE:-<none>}" >&2
    exit 2
fi
if [[ $LIST_ONLY == 1 ]]; then
    printf '%s\n' "${CASES[@]}"
    exit 0
fi

passed=0
flaky=0
failed=0
xfailed=0
xpassed=0
for fixture in "${CASES[@]}"; do
    CASE_ENV=(env)
    generated_index=
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
    case_fuzz_area "$name" "$category" "$generated_index"
    current_case_area=$CASE_FUZZ_AREA
    out="$RESULTS/$category/$name"
    mkdir -p "$out"
    PROTO_ARGS=()
    SS_ARGS=(-"$IP_FAMILY" -ltnH "sport = :$PORT")
    max_attempts=1
    if [[ $name == udp_* || $name == capture_udp_* ]]; then
        PROTO_ARGS=(--udp)
        SS_ARGS=(-"$IP_FAMILY" -lunH "sport = :$PORT")
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
    case_safe_rejected=false
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
        # Malformed TLS fuzz inputs have two valid outcomes: an exact
        # plaintext traversal when mutation destroyed the TLS signature, or
        # an immediate fail-closed teardown when autodetection retained it.
        # Do not turn a security-preserving TLS rejection into a flaky corpus
        # failure.  Timeouts, crashes and one-sided transport failures remain
        # failures; the dedicated autodetect suite independently proves that
        # recognizable TLS prefixes never reach the plaintext origin.
        tls_clean_close=false
        tls_early_reset=false
        if grep -q 'connection closed by peer' "$client_log" \
            && grep -q 'connection closed by peer' "$server_log"; then
            tls_clean_close=true
        fi
        # A strict detector can reset the sender while it is still writing a
        # fragmented malformed record. Pplay reports that as Broken pipe and
        # leaves its origin actor waiting for bytes that must never arrive.
        # Accept only that asymmetric outcome: the client must fail promptly,
        # and the origin log must prove that it received no payload at all.
        if grep -Eq 'Broken pipe|connection closed by peer' "$client_log" \
            && ! grep -Eqi 'DIE.AFTER|TIMEOUT|Traceback|AssertionError' "$client_log" \
            && ! grep -Eqi 'received [0-9]+B|has been received|DIFFERENT DATA' "$server_log"; then
            tls_early_reset=true
        fi
        if [[ $current_case_area == tls && $ready == true ]] \
            && { $tls_clean_close || $tls_early_reset; } \
            && ! grep -Eqi 'Traceback|AssertionError' "$client_log" "$server_log"; then
            case_safe_rejected=true
            passed_attempt=$case_attempt
            break
        fi
    done

    expected=false
    if [[ -r $EXPECTED_FAILURES_FILE ]] \
        && grep -Fqx "$category/$name" "$EXPECTED_FAILURES_FILE"; then
        expected=true
    fi

    if $case_safe_rejected; then
        printf '%-10s %-34s %s\n' "$category" "$name" "PASS${IP_FAMILY}_SAFE_REJECT"
        ((passed += 1))
    elif $case_passed; then
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

processed=$((passed + flaky + failed + xfailed))
if ((processed != ${#CASES[@]})); then
    echo "FAIL: corpus accounting mismatch selected=${#CASES[@]} processed=$processed" >&2
    exit 2
fi
echo "family=IPv$IP_FAMILY passed=$passed flaky=$flaky failed=$failed xfailed=$xfailed xpassed=$xpassed results=$RESULTS"
[[ $failed == 0 ]]
