FROM debian:10

ARG FTP_UPLOAD_PWD=""

WORKDIR /app

RUN if [ "$http_proxy" != "" ]; then echo "Acquire::http { Proxy \"${http_proxy}\"; };" >> /etc/apt/apt.conf.d/01proxy; fi;

RUN apt update && apt -y install git && DEBIAN_FRONTEND=noninteractive apt install -y tzdata

RUN git clone --depth 1 --recursive https://github.com/astibal/smithproxy.git -b master smithproxy

RUN cd smithproxy && ./tools/linux-deps.sh

RUN cd /app/smithproxy/tools/pkg-scripts/deb && ./createdeb-0.9.sh

CMD echo "there is nothing to see - it's a build-only image"