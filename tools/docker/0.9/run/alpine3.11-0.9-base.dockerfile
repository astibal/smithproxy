#
FROM alpine:3.11

LABEL org.smithproxy.docker.image="astibal/smithproxy:alpine3.11-0.9-base"

WORKDIR /app

RUN apk update && apk add git

RUN git clone --recursive https://github.com/astibal/smithproxy.git -b master smithproxy

RUN cd smithproxy && ./tools/linux-deps.sh
