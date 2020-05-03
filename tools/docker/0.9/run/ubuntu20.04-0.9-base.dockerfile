#
FROM ubuntu:20.04

LABEL org.smithproxy.docker.image="astibal/smithproxy:ubuntu20.04-0.9-base"

WORKDIR /app

RUN apt update && apt -y install git && DEBIAN_FRONTEND=noninteractive apt-get install -y tzdata

RUN git clone --recursive https://github.com/astibal/smithproxy.git -b master smithproxy

RUN cd smithproxy && ./tools/linux-deps.sh
