#!/bin/sh

# RUN THIS SCRIPT FROM ITS DIR 

MYPW=`pwd`
BUILD_DIR=/tmp/

mkdir $BUILD_DIR/sx

sudo docker build $1 ${BUILD_DIR}/sx -f ../../docker/0.9/run/ubuntu20.04-0.9-run.dockerfile --tag  astibal/smithproxy:ubuntu20.04-0.9-run-local

sudo ./runsx.sh ubuntu20.04-0.9-run-local
sudo ./redir-output-chain.sh start



