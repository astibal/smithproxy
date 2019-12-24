# 
FROM debian:stretch AS builder

# Set the working directory to /app
WORKDIR /app

RUN apt update && apt install -y \
               bash wget curl python-pip \
               libcli1.9 libconfig++9v5 libssl1.0 libunwind8 libconfig++ && \
apt install -y iptables python-ldap python-pyparsing python-posix-ipc python-soappy python-m2crypto telnet iproute2 && \
apt install -y libconfig-dev libcli-dev libunwind-dev libssl1.0-dev \
               debootstrap devscripts build-essential lintian vim nano\
               git g++ cmake make && \
pip install pylibconfig2

RUN \
    git clone https://github.com/astibal/socle.git socle -b 0.8 && \
    git clone https://github.com/astibal/smithproxy.git smithproxy -b 0.8 && \
    \
    cd smithproxy && mkdir build && cd build && cmake .. && make install

CMD cd /app/smithproxy/tools/build-scripts/deb && echo "run ./createdeb-0.8.sh <upload password> <socle_branch> <smithproxy_branch>" && /bin/bash
