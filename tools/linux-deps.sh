#!/usr/bin/env bash

eval `cat /etc/lsb-release`


SX_LIBCLI_VER="1.9"
SX_LIBCONFIG_VER="9v5"
SX_GCC_VER="8"
SX_SPYNE_VER="==2.13.2a0"

if [[ "${DISTRIB_ID}" == "Ubuntu" ]]; then
   if [[ "${DISTRIB_RELEASE}" == "20.04" ]]; then
        SX_LIBCLI_VER="1.10"
        SX_LIBCONFIG_VER="9v5"
        SX_GCC_VER="9"
   fi

    DEBIAN_FRONTEND=noninteractive apt-get install -y tzdata

    echo "... installing essentials and libraries"
    apt update && apt install -y \
    wget curl \
    python3 python3-pip python3-dev \
    libcli${SX_LIBCLI_VER} libconfig++${SX_LIBCONFIG_VER} libssl1.1 libunwind8 \
    libcli-dev libconfig-dev libconfig++-dev  libssl-dev libunwind-dev git g++-${SX_GCC_VER} cmake make

    echo "... installing OS toolchains"
    apt install -y iptables telnet iproute2 && \
    apt install -y python3-ldap python3-pyparsing python3-posix-ipc swig  \
    debootstrap devscripts build-essential lintian debhelper vim nano

elif [[ "${DISTRIB_ID}" == "SomeOtherSupportedDistro" ]]; then
    true;
else
    echo "We can't detect your distro."
    echo "please make sure following development packages are installed to compile smithproxy:"
    echo "   libcli-dev"
    echo "   libconfig++-dev"
    echo "   libssl-dev"
    echo "   python-dev"
    echo "   libunwind-dev (version8)"
    echo "   "
    echo "and following packages to make smithproxy infrastructure work:"
    echo "   iptables telnet iproute2 python3 swig"
    echo "   ... python3 packages: ldap pyparsing posix-ipc pyroute2 pylibconfig2 m2crypto spyne==2.13.2a0 zeep cryptography"

    exit 1;
fi




echo "... using GCC ${SX_GCC_VER}"
ln -sf /usr/bin/g++-${SX_GCC_VER} /usr/bin/g++ && \
ln -sf /usr/bin/g++-${SX_GCC_VER} /usr/bin/c++ && \
ln -sf /usr/bin/gcc-${SX_GCC_VER} /usr/bin/gcc && \
ln -sf /usr/bin/gcc-${SX_GCC_VER} /usr/bin/cc && \
ln -sf /usr/bin/gcc-ar-${SX_GCC_VER} /usr/bin/gcc-ar

echo "... installing python libraries"
pip3 install pyroute2 pylibconfig2 m2crypto spyne${SX_SPYNE_VER} zeep cryptography


