#
FROM ubuntu:18.04

LABEL org.smithproxy.docker.image="astibal/smithproxy:ubuntu18.04-0.9-base"

# Set the working directory to /app
WORKDIR /app

RUN apt update && apt install -y \
wget curl \
python3 python3-pip python3-dev \
libcli1.9 libconfig++9v5 libssl1.1 libunwind8 \
libcli-dev libconfig-dev libconfig++-dev  libssl-dev libunwind-dev

RUN apt install -y iptables telnet iproute2 && \
apt install -y python3-ldap python3-pyparsing python3-posix-ipc swig  \
debootstrap devscripts build-essential lintian debhelper vim nano \
git g++-8 cmake make

RUN pip3 install pyroute2 pylibconfig2 m2crypto spyne zeep

RUN ln -sf /usr/bin/g++-8 /usr/bin/g++ && \
ln -sf /usr/bin/g++-8 /usr/bin/c++ && \
ln -sf /usr/bin/gcc-8 /usr/bin/gcc && \
ln -sf /usr/bin/gcc-8 /usr/bin/cc && \
ln -sf /usr/bin/gcc-ar-8 /usr/bin/gcc-ar

