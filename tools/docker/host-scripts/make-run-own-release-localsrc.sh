#!/bin/sh

# RUN THIS SCRIPT FROM ITS DIR 

P=`pwd`

export SRC="$HOME/pro/smithproxy"
export DST="`mktemp -d --suffix smithproxy`"
cp -r $SRC $DST && cd $DST
rm -rf smithproxy/cmake-build* ; rm -rf smithproxy/build ; rm -rf smithproxy/venv ; rm smithproxy/*.snap
sudo docker build . -f smithproxy/tools/docker/0.9/run/ubuntu20.04-0.9-release-localsrc.dockerfile --tag astibal/smithproxy:ubuntu20.04-0.9-run-release-localsrc
cd ${P}

sudo ./runsx-debug.sh ubuntu20.04-0.9-run-release-localsrc
sudo ./redir-output-chain.sh start



