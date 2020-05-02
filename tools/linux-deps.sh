#!/usr/bin/env sh

SX_LIBCLI_VER="1.9"
SX_LIBCONFIG_VER="9v5"
SX_GCC_VER="8"
SX_SPYNE_VER=">=2.13.2a0"


OS=`uname -s`
REV=`uname -r`
MACH=`uname -m`
DIST="UnknownDist"
REV="UnknownRev"

LINK_TOOLCHAIN="Y"

# taken from distro.sh in pkg-scripts/deb/

### detect OS

if [ "${OS}" = "SunOS" ] ; then
	OS=Solaris
	ARCH=`uname -p`
	OSSTR="${OS} ${REV}(${ARCH} `uname -v`)"
elif [ "${OS}" = "AIX" ] ; then
	OSSTR="${OS} `oslevel` (`oslevel -r`)"
elif [ "${OS}" = "Linux" ] ; then
	KERNEL=`uname -r`


	if [ -f /etc/fedora-release ] ; then
		DIST='Fedora'
		PSEUDONAME=`cat /etc/fedora-release | sed s/.*\(// | sed s/\)//`

		REV=`cat /etc/fedora-release | sed s/.*release\ // | sed s/\ .*//`
	elif [ -f /etc/redhat-release ] ; then
		DIST='RedHat'
		PSEUDONAME=`cat /etc/redhat-release | sed s/.*\(// | sed s/\)//`
		REV=`cat /etc/redhat-release | sed s/.*release\ // | sed s/\ .*//`

	elif [ -f /etc/SUSE-release ] ; then
		DIST=`cat /etc/SUSE-release | tr "\n" ' '| sed s/VERSION.*//`
		REV=`cat /etc/SUSE-release | tr "\n" ' ' | sed s/.*=\ //`

	elif [ -f /etc/mandrake-release ] ; then
		DIST='Mandrake'
		PSEUDONAME=`cat /etc/mandrake-release | sed s/.*\(// | sed s/\)//`
		REV=`cat /etc/mandrake-release | sed s/.*release\ // | sed s/\ .*//`

	elif [ -f /etc/lsb-release ] ; then
		eval `cat /etc/lsb-release`
		DIST=$DISTRIB_ID
		PSEUDONAME=$DISTRIB_CODENAME
		REV=$DISTRIB_RELEASE

	elif [ -f /etc/debian_version ] ; then
		DIST="Debian"
		REV="`cat /etc/debian_version | awk -F"/" '{ print $1 }' | awk -F"." '{ print $1 }'`"

		if [ "${REV}" = "bullseye" ]; then
		    REV="11.0"
		fi

    elif [ -f /etc/alpine-release ] ; then
        DIST="Alpine"
        MAJ=`cat /etc/alpine-release | tr '_' ' ' | tr '.' ' ' | awk '{ print $1 }' `
        MIN=`cat /etc/alpine-release | tr '_' ' ' | tr '.' ' ' | awk '{ print $2 }' `
        REV="${MAJ}.${MIN}"

	elif [ -f /etc/UnitedLinux-release ] ; then
		DIST="${DIST}[`cat /etc/UnitedLinux-release | tr "\n" ' ' | sed s/VERSION.*//`]"
	fi

	OSSTR="${OS} ${DIST} ${REV}(${PSEUDONAME} ${KERNEL} ${MACH})"

fi

###

echo "... OS detected: $DIST version $REV"

if [ "${DIST}" = "Ubuntu" ]; then

   # specifics
   if [ "${REV}" = "20.04" ]; then
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

    echo "... installing python libraries"
    pip3 install --upgrade pip
    pip3 install pyroute2 pylibconfig2 m2crypto spyne${SX_SPYNE_VER} zeep cryptography

elif [ "${DIST}" = "Debian" ]; then

    DEB_MAJ=`echo $REV | awk -F'.' '{ print $1 }'`

    if [ "${DEB_MAJ}" = "11" ]; then
        SX_LIBCLI_VER="1.10"
        SX_LIBCONFIG_VER="9v5"
        SX_GCC_VER="10"
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
    apt install -y python3-ldap python3-pyparsing swig  \
    debootstrap devscripts build-essential lintian debhelper vim nano

    echo "... installing python libraries"
    pip3 install --upgrade pip

    if [ "${MACH}" = "aarch64" ]; then
        apt install -y python3-lxml
    fi

    if [ "${DEB_MAJ}" = "11" ]; then
        apt install -y python3-m2crypto
        pip3 install posix-ipc
        pip3 install pyroute2 pylibconfig2 spyne${SX_SPYNE_VER} zeep cryptography
    else
        apt install -y python3-posix-ipc
        pip3 install pyroute2 pylibconfig2 m2crypto spyne${SX_SPYNE_VER} zeep cryptography
    fi

elif [ "${DIST}" = "Alpine" ]; then

    OPW=`pwd`

    cd /tmp

    apk update
    apk add git bash
    apk add make gcc musl-dev

    git clone --recursive https://github.com/dparrish/libcli
    cd libcli/ && make install && cp libcli.h /usr/include/ && cd ..

    apk add libconfig libconfig-dev
    apk add cmake g++ python3-dev libexecinfo-dev openssl-dev linux-headers libunwind-dev
    apk add busybox-extras iptables iproute2
    apk add py-pip
    apk add libldap openldap-dev libffi-dev libxml2-dev xmlsec-dev swig

    pip3 install --upgrade pip
    pip3 install python-ldap pyparsing posix-ipc
    pip3 install pyroute2 pylibconfig2 m2crypto spyne${SX_SPYNE_VER} zeep cryptography

    LINK_TOOLCHAIN="N"

    cd ${OPW}

elif [ "${DIST}" = "Fedora" ]; then

    OPW=`pwd`
    yum update -y
    yum install -y git openssl-libs openssl-devel libcli-devel libconfig-devel python3-devel libunwind-devel kernel-headers glibc-headers

    yum install -y gcc-c++ cmake make
    yum install -y telnet iptables iproute
    yum install -y openldap-devel libffi-devel libxml2-devel swig
    yum install -y python3-pip
    pip install --upgrade pip
    pip install wheel
    pip install python-ldap pyparsing posix-ipc
    pip install pyroute2 pylibconfig2 m2crypto spyne${SX_SPYNE_VER} zeep cryptography
    LINK_TOOLCHAIN="N"

    cd ${OPW}
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



if [ "${LINK_TOOLCHAIN}" = "Y" ]; then
    echo "... using GCC ${SX_GCC_VER}"
    ln -sf /usr/bin/g++-${SX_GCC_VER} /usr/bin/g++ && \
    ln -sf /usr/bin/g++-${SX_GCC_VER} /usr/bin/c++ && \
    ln -sf /usr/bin/gcc-${SX_GCC_VER} /usr/bin/gcc && \
    ln -sf /usr/bin/gcc-${SX_GCC_VER} /usr/bin/cc && \
    ln -sf /usr/bin/gcc-ar-${SX_GCC_VER} /usr/bin/gcc-ar
fi
