#!/bin/bash

TAG="testing"

TMPFS="no"
LOG_VOLUME="--mount type=tmpfs,destination=/var/log,tmpfs-size=1000000000"

if [ "$1" != "" ]; then
    TAG=$1
    shift
fi

( sudo docker inspect sxy ) > /dev/null 2>&1; 
SXY_=$?
( sudo docker inspect sxyvar ) > /dev/null 2>&1; 
SXYVAR_=$?
( sudo docker inspect sxydumps ) > /dev/null 2>&1; 
SXYDUMPS_=$?

#echo "etc volume: $SXY_"
#echo "var  volume: $SXYVAR_"
#echo "dumps volume: $SXYDUMPS_"

if [ "$SXY_" != "0" ]; then
    echo "... creating /etc volume"
    sudo docker volume create sxy
fi

if [ "$TMPFS" != "yes" ]; then
    if [ "$SXYVAR_" != "0" ]; then
        echo "... creating /var/log volume"
        sudo docker volume create sxyvar
    fi
    LOG_VOLUME="-v sxyvar:/var/log"
fi
    
if [ "$SXYDUMPS_" != "0" ]; then
    echo "... creating /var/local/smithproxy volume"
    sudo docker volume create sxydumps
fi


#	 \

sudo docker pull astibal/smithproxy:${TAG}
sudo docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined\
	-v sxy:/etc/smithproxy \
	${LOG_VOLUME} \
	-v sxydumps:/var/local/smithproxy \
	-it \
	--rm --name "sx-${TAG}-`date +"%s"`" astibal/smithproxy:${TAG} "$@"
