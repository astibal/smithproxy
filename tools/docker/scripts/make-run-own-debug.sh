#!/bin/sh

# RUN THIS SCRIPT FROM ITS DIR 

BUILD_DIR=`mktmp -d`
mkdir $BUILD_DIR/sx

sudo docker build ${BUILD_DIR}/sx -f ../../docker/0.9/run/ubuntu18.04-0.9-base.dockerfile --tag  astibal/smithproxy:ubuntu18.04-0.9-base
sudo docker build --no-cache $1 ${BUILD_DIR}/sx -f ../../docker/0.9/run/ubuntu18.04-0.9-debug.dockerfile --tag  astibal/smithproxy:ubuntu18.04-0.9-run-dbg-local

sudo ./runsx-debug.sh ubuntu18.04-0.9-run-dbg-local
sudo ./redir-output-chain.sh start



