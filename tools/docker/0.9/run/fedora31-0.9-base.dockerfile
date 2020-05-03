#
FROM fedora:31

LABEL org.smithproxy.docker.image="astibal/smithproxy:fedora31-0.9-base"

WORKDIR /app

RUN yum -y update && yum install -y git

RUN git clone --recursive https://github.com/astibal/smithproxy.git -b master smithproxy

RUN cd smithproxy && ./tools/linux-deps.sh
