FROM ubuntu:20.04

LABEL org.smithproxy.docker.image="astibal/smithproxy:0.9.30"

WORKDIR /app

RUN apt update && apt -y install curl wget ca-certificates &&  \
    cd /tmp/ && curl https://download.smithproxy.org/0.9/Linux-Ubuntu-20.04/release/smithproxy_0.9.30-1_amd64.deb --output smithproxy_0.9.30-1_amd64.deb && \
    dpkg -i smithproxy_0.9.30-1_amd64.deb ; apt -yf --no-install-recommends --no-install-suggests install && /usr/bin/sx_download_ctlog

CMD echo "Starting smithproxy .... " && /usr/bin/smithproxy