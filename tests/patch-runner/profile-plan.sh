#!/usr/bin/env bash
# Canonical patch-runner profile composition.  Both standalone profiles and
# `full` consume this list, so full cannot grow a second, similar test suite.

PATCH_RUNNER_FULL_PROFILES=(native sanity traffic lifecycle corpus fuzz)
PATCH_RUNNER_REPORTABLE_PROFILES=(native sanity traffic lifecycle corpus fuzz coverage fuzz-dyn benchmark)
# Capture is a matrix, not one successful exporter hiding a broken sibling.
PATCH_RUNNER_CAPTURE_SECTIONS=(capture-traffic capture-pcapng quic quic-pcapng)
mapfile -t PATCH_RUNNER_QUIC_CERT_SECTIONS < <(python3 "$(dirname "${BASH_SOURCE[0]}")/harness/suites/tls/certificate_cases.py")
((${#PATCH_RUNNER_QUIC_CERT_SECTIONS[@]} > 0)) || return 1
PATCH_RUNNER_TRAFFIC_SECTIONS=(rtt tls-throughput tls-policy routing transfer tcp-churn udp-churn "${PATCH_RUNNER_CAPTURE_SECTIONS[@]}" "${PATCH_RUNNER_QUIC_CERT_SECTIONS[@]}")
PATCH_RUNNER_CORPUS_SECTIONS=()
for patch_runner_corpus_category in regular edge insanity; do
    for patch_runner_corpus_shard in 1 2 3 4; do
        PATCH_RUNNER_CORPUS_SECTIONS+=("corpus-$patch_runner_corpus_category.$patch_runner_corpus_shard")
    done
done
unset patch_runner_corpus_category patch_runner_corpus_shard

patch_runner_fuzz_sections() {
    local area category
    for area in "${FUZZ_AREAS[@]}"; do
        if [[ $area == h1 || $area == h2 ]]; then
            for category in regular edge insanity; do printf 'fuzz.%s.%s\n' "$area" "$category"; done
        else
            printf 'fuzz.%s\n' "$area"
        fi
    done
}

patch_runner_profile_sections() {
    local profile=$1
    case "$profile" in
        sanity) printf '%s\n' smoke ;;
        traffic) printf '%s\n' smoke "${PATCH_RUNNER_TRAFFIC_SECTIONS[@]}" ;;
        lifecycle) printf '%s\n' lifecycle ;;
        corpus) printf '%s\n' smoke "${PATCH_RUNNER_CORPUS_SECTIONS[@]}" ;;
        fuzz|fuzz-dyn) printf '%s\n' smoke; patch_runner_fuzz_sections ;;
        full)
            # Ordered union of the selected profiles. Native is handled by the
            # coordinator; repeated smoke dependencies collapse to one job.
            {
                patch_runner_profile_sections sanity
                patch_runner_profile_sections traffic
                patch_runner_profile_sections lifecycle
                patch_runner_profile_sections corpus
                patch_runner_profile_sections fuzz
            } | awk '!seen[$0]++'
            ;;
        *) return 2 ;;
    esac
}

patch_runner_profile_has_native() {
    [[ $1 == native || $1 == full ]]
}

patch_runner_section_profile() {
    local section=$1
    case "$section" in
        lifecycle) printf '%s\n' lifecycle ;;
        corpus-*) printf '%s\n' corpus ;;
        fuzz.*) printf '%s\n' fuzz ;;
        rtt|tls-throughput|tls-policy|routing|transfer|quic|quic-pcapng|quic-cert.*|tcp-churn|udp-churn|capture|capture-traffic|capture-pcapng)
            printf '%s\n' traffic
            ;;
        *) printf '%s\n' sanity ;;
    esac
}
