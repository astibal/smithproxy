#!/bin/bash

SXPATH=$1

if [[ -z "$SXPATH" || ! -d "$SXPATH" ]]; then
    echo "Invalid or no path provided."
    exit 1
fi

declare -A components
declare -A versions

SX_LOG="/tmp/sx_log"
SO_LOG="/tmp/so_log"

components["$SX_LOG"]="Smithproxy"
components["$SO_LOG"]="Socle library"


GIT_DESCR=$(git -C "${SXPATH}" describe --tags)

GIT_TAG=$(echo "${GIT_DESCR}" | awk -F'-' '{ print $1 }')
GIT_PATCH_DIST=$(echo "${GIT_DESCR}" | awk -F'-' '{ print $2 }')

function process_component {
    local component_path=$1
    local log_file=$2

    if [[ ! -d "$component_path" ]]; then
        return 1
    fi

    cd "$component_path" || return 1
    git log --pretty=format:%s --oneline --output "${log_file}_pre"

    # Fetch the latest tag that matches the pattern x.y.z
    local latest_tag=$(git tag --list | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n 1)
    if [[ -z "$latest_tag" ]]; then
        return 1
    fi

    versions["$log_file"]=$latest_tag
    fmt -s --prefix="    " < "${log_file}_pre" > "$log_file"
}

process_component "$SXPATH" "$SX_LOG"
process_component "$SXPATH/socle" "$SO_LOG"

echo "smithproxy (${GIT_TAG}-${GIT_PATCH_DIST}) $(lsb_release -cs); urgency=medium"
echo

for f in "${SX_LOG}" "${SO_LOG}"; do
    echo
    echo "    ${components[$f]}-${versions[$f]}"
    echo
    awk '{
        max_length = 70;
        if (length($0) > max_length)
            print "    - " substr($0, 1, max_length - 3) "...";
        else
            print "    - " $0;
    }' "$f"
done

echo
echo " -- Support <support@smithproxy.org>  $(date -R)"
