#
FROM ubuntu:20.04

LABEL org.smithproxy.docker.image="astibal/smithproxy:ubuntu120.04-0.9-debug"

WORKDIR /app

RUN apt update && apt -y install git && DEBIAN_FRONTEND=noninteractive apt-get install -y tzdata

RUN git clone --recursive https://github.com/astibal/smithproxy.git -b master smithproxy

RUN cd smithproxy && ./tools/linux-deps.sh

RUN cd smithproxy && \
mkdir build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug && make install

# Define environment variable

# Run smithproxy when the container launches
CMD echo "Starting smithproxy .... " && ( /etc/init.d/smithproxy start ) > /dev/null 2>&1 && sleep 2 && \
    echo "SSL MITM CA cert:" && cat /etc/smithproxy/certs/default/ca-cert.pem && sx_cli && bash
