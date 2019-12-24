#
FROM ubuntu:18.04

# Set the working directory to /app
WORKDIR /app

RUN apt update && apt install -y \
wget curl \
python3 python3-pip python3-dev \
libcli1.9 libconfig++9v5 libssl1.1 libunwind8 libconfig++ \
libcli-dev libconfig-dev  libssl-dev libunwind-dev \
&& \
apt install -y iptables telnet iproute2 && \
apt install -y python3-ldap python3-pyparsing python3-posix-ipc swig  \
debootstrap devscripts build-essential lintian debhelper vim nano \
git g++8 cmake make && \
pip3 install pyroute2 pylibconfig2 m2crypto spyne zeep

