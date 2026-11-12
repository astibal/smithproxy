FROM debian:11

# Default packages use ngtcp2; legacy builds require an explicit build argument.
ARG SMITHPROXY_ENABLE_NGTCP2=ON
ENV SMITHPROXY_ENABLE_NGTCP2=${SMITHPROXY_ENABLE_NGTCP2}

ARG FTP_UPLOAD_PWD=""
ARG FTP_UPLOAD_USER=""
ARG FTP_UPLOAD_PATH=""
ARG HTTP_CHECK_PATH=""
ARG SX_BRANCH="master"
ARG CURL_UPLOAD_OPTS=""
ARG MAKE_DEBUG="Y"
ARG CHANNEL="snapshots"

WORKDIR /app

RUN if [ "$http_proxy" != "" ]; then echo "Acquire::http { Proxy \"${http_proxy}\"; };" >> /etc/apt/apt.conf.d/01proxy; fi;

RUN apt update && apt -y install git && DEBIAN_FRONTEND=noninteractive apt install -y tzdata

RUN echo "Getting git branch: ${SX_BRANCH}"; git clone --depth 1 --recursive https://github.com/astibal/smithproxy.git -b ${SX_BRANCH} smithproxy

RUN cd smithproxy && ./tools/linux-deps.sh

RUN apt-get install -y --no-install-recommends devscripts debhelper

RUN cd /app/smithproxy/tools/pkg-scripts/deb && ./createdeb-0.9.sh

CMD echo "there is nothing to see - it's a build-only image"