# Running smithproxy in docker
This is very easy way to test smithproxy! Just run it, you will have your 
testing smithproxy up in minutes, with permanent storage, certs, etc.
Still, you will maybe need to tune profiles and policies a bit.

**Docker smithproxy supports only SOCKS method. So you will
need to point your browser or app to it.**

## Socksifying a program
There are ways to *socksify* stubborn program.

##### Linux
 In linux, we actually have `socksify`, you can probably install it from  package manager.

##### Windows
In Windows, you need something similar to **InjectSOCKS**. But I have never tested that one,
so you need the right tool for you yourself. 

# The script
```
#!/bin/bash

TAG="latest"
TMPFS="yes"
EXTPORT="1080"

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

sudo docker pull astibal/smithproxy:${TAG}
sudo docker run -p ${EXTPORT}:1080 -v sxy:/etc/smithproxy \
        ${LOG_VOLUME} \
        -v sxydumps:/var/local/smithproxy \
        -it \
        --rm --network host --name "sx-${TAG}" astibal/smithproxy:${TAG} "$@"
```