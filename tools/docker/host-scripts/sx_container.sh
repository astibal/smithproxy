#!/bin/bash

TAG="latest"
TMPFS="no"
HOST_SHARED="yes"
NETWORK="host"
RUN_DAEMON="no"
RUN_DAEMON_ID="0"

RUN_CERTINFO="no"
RUN_CLI="no"
DRY="no"

function explain {
   echo "Image tag: ${TAG}"
   echo
   echo "Container: ${RUN_DAEMON} (instance ID ${RUN_DAEMON_ID})"
   echo "Using host data: ${HOST_SHARED}"
   echo "Using network: ${NETWORK}"
   echo
   echo "will use ramdisk: ${TMPFS}"
   echo
   echo "will show ca cert: ${RUN_CERTINFO}"
}

while [ ! -z "$1" ]; do

    if [ "$1" == "--help" ]; then
      shift
      echo """
        --dry          don't actually act, just explain and exit. SAFE.

        --run          start the daemon
        --id           instance ID (defaults to 0, useful only together with --volumes private instances)
        --sx_cli       start CLI
        --certinfo_ca  show CA certificate


        --help         print this help
        --tag          use specific tag from astibal/smithoxy:<tag>
        --volumes      don't use host directories, use volumes (will be created)
        --tmpfs        use ramdisk for temporary data

      """

    elif [ "$1" == "--tag" ]; then
        shift
        TAG="$1"
        shift

    elif [ "$1" == "--volumes" ]; then
        shift
        HOST_SHARED="no"


    elif [ "$1" == "--tmpfs" ]; then
        shift
        TMPFS="yes"

        echo "using tmpfs: {$TMPFS}"

    elif [ "$1" == "--run" ]; then
        shift
        RUN_DAEMON="yes"

    elif [ "$1" == "--network" ]; then
        shift
        NETWORK="$1"
        shift

    elif [ "$1" == "--id" ]; then
        shift
        RUN_DAEMON_ID="$1"
        shift

    elif [ "$1" == "--certinfo_ca" ]; then
        shift
        RUN_CERTINFO="yes"

    elif [ "$1" == "--cli" ]; then
        shift
        RUN_CLI="yes"

    elif [ "$1" == "--dry" ]; then
        shift

        explain
        DRY="yes"
    fi

done

if [ "${DRY}" == "yes" ]; then
    echo "DRY MODE, exiting"
    exit 1
fi

# docker run astibal/smithproxy:latest sh -c "/usr/bin/sx_certinfo_ca"

LOG_VOLUME1="--mount"
LOG_VOLUME2="type=tmpfs,destination=/var/log,tmpfs-size=1000000000"

function run_docker_private {
    docker run --rm -d --cap-add=NET_ADMIN --shm-size 512M \
      -v sxy"${RUN_DAEMON_ID}":/etc/smithproxy \
      "${LOG_VOLUME1}" "${LOG_VOLUME2}" \
      -v sxydumps"${RUN_DAEMON_ID}":/var/local/smithproxy \
      --network "${NETWORK}" --name "sx-${TAG}-${RUN_DAEMON_ID}" astibal/smithproxy:"${TAG}"
}

function run_docker_private_cmd {
    docker run --rm --cap-add=NET_ADMIN --shm-size 512M \
      -v sxy:/etc/smithproxy \
      "${LOG_VOLUME1}" "${LOG_VOLUME2}" \
      -v sxydumps:/var/local/smithproxy \
      --network "${NETWORK}" astibal/smithproxy:"${TAG}" "$@"
}



function run_docker_host {
    docker run --rm -d --cap-add=NET_ADMIN --shm-size 512M \
    "${LOG_VOLUME1}" "${LOG_VOLUME2}" \
    --mount type=bind,source=/etc/smithproxy,target=/etc/smithproxy \
    --mount type=bind,source=/var/local/smithproxy,target=/var/local/smithproxy \
    --network "${NETWORK}" --name sx-"${TAG}-${RUN_DAEMON_ID}" astibal/smithproxy:"${TAG}"
}
function run_docker_host_cmd {
    docker run --rm --cap-add=NET_ADMIN --shm-size 512M \
    "${LOG_VOLUME1}" "${LOG_VOLUME2}" \
    --mount type=bind,source=/etc/smithproxy,target=/etc/smithproxy \
    --mount type=bind,source=/var/local/smithproxy,target=/var/local/smithproxy \
    --network "${NETWORK}" astibal/smithproxy:"${TAG}" "$@"
}

function run_docker_cmd {
    docker exec -it sx-"${TAG}-${RUN_DAEMON_ID}" "$@"
}



function directory_setup {
    if [ "${HOST_SHARED}" != "yes" ]; then

        ( docker inspect sxy"${RUN_DAEMON_ID}" ) > /dev/null 2>&1;
        SXY_=$?
        ( docker inspect sxyvars"${RUN_DAEMON_ID}" ) > /dev/null 2>&1;
        SXYVAR_=$?
        ( docker inspect sxydumps"${RUN_DAEMON_ID}" ) > /dev/null 2>&1;
        SXYDUMPS_=$?

        #echo "etc volume: $SXY_"
        #echo "var  volume: $SXYVAR_"
        #echo "dumps volume: $SXYDUMPS_"

        if [ "$SXY_" != "0" ]; then
            echo "... creating /etc volume"
            docker volume create sxy"${RUN_DAEMON_ID}"
        fi

        if [ "$TMPFS" != "yes" ]; then
            if [ "$SXYVAR_" != "0" ]; then
                echo "... creating /var/log volume"
                docker volume create sxyvars"${RUN_DAEMON_ID}"
            fi
            LOG_VOLUME1="-v"
            LOG_VOLUME2="sxyvars${RUN_DAEMON_ID}:/var/log/smithproxy"
        fi

        if [ "$SXYDUMPS_" != "0" ]; then
            echo "... creating /var/local/smithproxy volume"
            docker volume create sxydumps"${RUN_DAEMON_ID}"
        fi

    else
        LOG_VOLUME2="type=tmpfs,destination=/var/log/smithproxy,tmpfs-size=1000000000"
        if [ "${TMPFS}" != "yes" ]; then
            LOG_VOLUME2="type=bind,source=/var/log/smithproxy,target=/var/log/smithproxy"
        fi

        if [ ! -d /var/local/smithproxy ]; then
            mkdir /var/local/smithproxy
        fi
    fi
}


directory_setup

if [ "${RUN_CERTINFO}" == "yes" ]; then
  run_docker_cmd "/usr/bin/sx_certinfo_ca"
fi

if [ "${RUN_CLI}" == "yes" ]; then
  run_docker_cmd "/usr/bin/sx_cli"
fi


if [ "${HOST_SHARED}" == "yes" ]; then
    if [ "${RUN_DAEMON}" == "yes" ]; then
        run_docker_host
    fi
else
    if [ "${RUN_DAEMON}" == "yes" ]; then
        run_docker_private
    fi
fi