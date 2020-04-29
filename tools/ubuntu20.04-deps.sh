#!/usr/bin/env bash

apt update && apt install -y \
wget curl \
python3 python3-pip python3-dev \
libcli1.10 libconfig++9v5 libssl1.1 libunwind8 \
libcli-dev libconfig-dev libconfig++-dev  libssl-dev libunwind-dev git g++-9 cmake make

apt install -y iptables telnet iproute2 && \
apt install -y python3-ldap python3-pyparsing python3-posix-ipc swig  \
debootstrap devscripts build-essential lintian debhelper vim nano

ln -sf /usr/bin/g++-9 /usr/bin/g++ && \
ln -sf /usr/bin/g++-9 /usr/bin/c++ && \
ln -sf /usr/bin/gcc-9 /usr/bin/gcc && \
ln -sf /usr/bin/gcc-9 /usr/bin/cc && \
ln -sf /usr/bin/gcc-ar-9 /usr/bin/gcc-ar

pip3 install pyroute2 pylibconfig2 m2crypto spyne zeep cryptography

