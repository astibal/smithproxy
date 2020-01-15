#!/bin/sh

# RUN THIS SCRIPT FROM ITS DIR 

MYPW=`pwd`
BUILD_DIR=/tmp/

mkdir $BUILD_DIR/sx

sudo docker build ${BUILD_DIR}/sx -f ../../docker/0.9/run/ubuntu18.04-0.9-base.dockerfile --tag  astibal/smithproxy:ubuntu18.04-0.9-base
sudo docker build ${BUILD_DIR}/sx -f ../../docker/0.9/run/ubuntu18.04-0.9.dockerfile --tag  astibal/smithproxy:ubuntu18.04-0.9-run



