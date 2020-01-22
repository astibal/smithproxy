#!/bin/sh

# RUN THIS SCRIPT FROM ITS DIR 

BUILD_DIR=`mktemp -d`
mkdir $BUILD_DIR/sx

cp -r ../../../../smithproxy/ $BUILD_DIR/sx

rm -rf $BUILD_DIR/sx/smithproxy/cmake-*
rm -rf $BUILD_DIR/sx/smithproxy/build
rm -rf $BUILD_DIR/sx/smithproxy/venv

sudo docker build ${BUILD_DIR}/sx -f ../../docker/0.9/run/ubuntu18.04-0.9-base.dockerfile --tag  astibal/smithproxy:ubuntu18.04-0.9-base
sudo docker build --no-cache $1 ${BUILD_DIR}/sx -f ../../docker/0.9/run/ubuntu18.04-0.9-debug-localsrc.dockerfile --tag  astibal/smithproxy:ubuntu18.04-0.9-run-dbg-localsrc

sudo ./runsx-debug.sh ubuntu18.04-0.9-run-dbg-localsrc
sudo ./redir-output-chain.sh start



