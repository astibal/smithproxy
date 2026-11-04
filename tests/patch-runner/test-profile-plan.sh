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
[[ " ${full[*]} " == *" corpus-insanity "* ]]
[[ " ${full[*]} " == *" fuzz.h2.insanity "* ]]
[[ ${PATCH_RUNNER_FULL_PROFILES[*]} == "native sanity traffic lifecycle corpus fuzz" ]]
[[ ${PATCH_RUNNER_REPORTABLE_PROFILES[*]} == "native sanity traffic lifecycle corpus fuzz coverage fuzz-dyn benchmark" ]]
mapfile -t lifecycle < <(patch_runner_profile_sections lifecycle)
[[ ${lifecycle[*]} == lifecycle ]]
mapfile -t corpus < <(patch_runner_profile_sections corpus)
[[ ${corpus[*]} == "smoke corpus-regular corpus-edge corpus-insanity" ]]
mapfile -t traffic < <(patch_runner_profile_sections traffic)
[[ ${traffic[*]} == "smoke ${PATCH_RUNNER_TRAFFIC_SECTIONS[*]}" ]]
[[ $(patch_runner_section_profile rtt) == traffic ]]
[[ $(patch_runner_section_profile lifecycle) == lifecycle ]]
[[ $(patch_runner_section_profile corpus-edge) == corpus ]]
[[ $(patch_runner_section_profile fuzz.tls) == fuzz ]]
[[ $(patch_runner_section_profile policy) == sanity ]]
echo "PASS: full is the ordered union of native, sanity, traffic, lifecycle, corpus and fuzz"
