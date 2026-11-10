#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
FUZZ_AREAS=(h1 h2 tls)
# shellcheck source=profile-plan.sh
source "$HERE/profile-plan.sh"

mapfile -t full < <(patch_runner_profile_sections full)
mapfile -t expected < <(
    for profile in sanity traffic lifecycle corpus fuzz; do
        patch_runner_profile_sections "$profile"
    done | awk '!seen[$0]++'
)
[[ ${full[*]} == "${expected[*]}" ]]
[[ $(printf '%s\n' "${full[@]}" | grep -cx smoke) == 1 ]]
[[ " ${full[*]} " == *" lifecycle "* ]]
[[ " ${full[*]} " == *" corpus-insanity.4 "* ]]
[[ " ${full[*]} " == *" fuzz.h2.insanity "* ]]
[[ ${PATCH_RUNNER_FULL_PROFILES[*]} == "native sanity traffic lifecycle corpus fuzz" ]]
[[ ${PATCH_RUNNER_REPORTABLE_PROFILES[*]} == "native sanity traffic lifecycle corpus fuzz coverage fuzz-dyn benchmark" ]]
mapfile -t lifecycle < <(patch_runner_profile_sections lifecycle)
[[ ${lifecycle[*]} == lifecycle ]]
mapfile -t corpus < <(patch_runner_profile_sections corpus)
[[ ${#corpus[@]} == 13 ]]
[[ ${corpus[*]} == "smoke corpus-regular.1 corpus-regular.2 corpus-regular.3 corpus-regular.4 corpus-edge.1 corpus-edge.2 corpus-edge.3 corpus-edge.4 corpus-insanity.1 corpus-insanity.2 corpus-insanity.3 corpus-insanity.4" ]]
mapfile -t traffic < <(patch_runner_profile_sections traffic)
[[ ${traffic[*]} == "smoke ${PATCH_RUNNER_TRAFFIC_SECTIONS[*]}" ]]
[[ $(patch_runner_section_profile rtt) == traffic ]]
[[ $(patch_runner_section_profile lifecycle) == lifecycle ]]
[[ $(patch_runner_section_profile corpus-edge.3) == corpus ]]
[[ $(patch_runner_section_profile fuzz.tls) == fuzz ]]
[[ $(patch_runner_section_profile policy) == sanity ]]
[[ ${PATCH_RUNNER_CAPTURE_SECTIONS[*]} == 'capture-traffic capture-pcapng quic quic-pcapng' ]]
for section in "${PATCH_RUNNER_CAPTURE_SECTIONS[@]}"; do
    [[ " ${full[*]} " == *" $section "* ]]
    [[ $(patch_runner_section_profile "$section") == traffic ]]
done
echo "PASS: full is the ordered union of native, sanity, traffic, lifecycle, corpus and fuzz"
