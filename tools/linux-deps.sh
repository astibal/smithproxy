#!/usr/bin/env sh

SX_LIBCONFIG_VER="9v5"
SX_GCC_VER="8"


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

  PIP="pip3"

   LIBSSL="libssl1.1"
   # specifics
   if [ "${REV}" = "20.04" ]; then
        SX_LIBCONFIG_VER="9v5"
        SX_GCC_VER="9"
   elif [ "${REV}" = "21.04" ]; then
        SX_LIBCONFIG_VER="9v5"
        SX_GCC_VER="11"
   elif [ "${REV}" = "22.04" ]; then
        SX_LIBCONFIG_VER="9v5"
        SX_GCC_VER="12"
        LIBSSL="libssl3"
        PIP="pip"
   fi

    DEBIAN_FRONTEND=noninteractive apt-get install -y tzdata

    echo "... installing essentials and libraries"
    apt update && apt install -y \
    wget curl \
    python3 python3-pip python3-dev \
    libconfig++${SX_LIBCONFIG_VER} ${LIBSSL} libunwind8 libmicrohttpd12 \
    libconfig-dev libconfig++-dev  libssl-dev libunwind-dev libmicrohttpd-dev git g++-${SX_GCC_VER} cmake make

    echo "... installing OS toolchains"
    apt install -y iptables telnet iproute2 python3-cryptography python3-pyroute2 \
    debootstrap devscripts build-essential lintian debhelper vim nano

    echo "... installing python libraries"
    ${PIP} install --upgrade pip
    ${PIP} install pyparsing  pylibconfig2

elif [ "${DIST}" = "Debian" ]; then

    # detect debian derivatives

    if   [ "${REV}" = "kali" ]; then
        DEB_MAJ="11"
        SX_LIBCONFIG_VER="9v5"
        SX_GCC_VER="9"

    elif [ "${REV}" = "kali-rolling" ]; then
        DEB_MAJ="11"
        SX_LIBCONFIG_VER="9v5"
        SX_GCC_VER="9"
    else
        # for vanilla Debians

        DEB_MAJ=`echo $REV | awk -F'.' '{ print $1 }'`

        if [ "${DEB_MAJ}" = "11" ]; then
            SX_LIBCONFIG_VER="9v5"
            SX_GCC_VER="10"
        fi

    fi


    DEBIAN_FRONTEND=noninteractive apt-get install -y tzdata

    echo "... installing essentials and libraries"
    apt update && apt install -y \
    wget curl \
    python3 python3-pip python3-dev \
    libconfig++${SX_LIBCONFIG_VER} libssl1.1 libunwind8 libmicrohttpd12 \
    libconfig-dev libconfig++-dev  libssl-dev libunwind-dev libmicrohttpd-dev git g++-${SX_GCC_VER} cmake make

    echo "... installing OS toolchains"
    apt install -y iptables telnet iproute2 && \
    apt install -y swig  \
    debootstrap devscripts build-essential lintian debhelper vim nano
    apt install -y libffi-dev

    echo "... installing python libraries"
    ${PIP} install --upgrade pip

    if [ "${MACH}" = "aarch64" ]; then
      echo
    fi

    if [ "${DEB_MAJ}" = "11" ]; then
        ${PIP} install pyparsing pylibconfig2
    else
        ${PIP} install pyparsing pylibconfig2
    fi

elif [ "${DIST}" = "Alpine" ]; then

    OPW=`pwd`

    cd /tmp

    apk update
    apk add git bash
    apk add make gcc musl-dev

    apk add openssl libconfig libconfig-dev libmicrohttpd libmicrohttpd-dev
    apk add cmake g++ python3-dev libexecinfo-dev openssl-dev linux-headers libunwind-dev
    apk add busybox-extras iptables iproute2
    apk add libffi-dev libxml2-dev libxslt-dev xmlsec-dev

    apk add py3-pip
    apk add py3-cryptography

    # add packages unknown to apk from pip3
    pip3 install --upgrade pip
    pip3 install wheel
    pip3 install pyroute2 pyparsing pylibconfig2

    LINK_TOOLCHAIN="N"

    cd ${OPW}

elif [ "${DIST}" = "Fedora" ]; then

    OPW=`pwd`
    yum update -y
    yum install -y git openssl-libs openssl-devel libconfig-devel python3-devel libunwind-devel kernel-headers glibc-headers
    yum install -y libmicrohttpd libmicrohttpd-devel

    yum install -y gcc-c++ cmake make
    yum install -y telnet iptables iproute
    yum install -y libffi-devel libxml2-devel swig
    yum install -y python3-pip
    pip install --upgrade pip
    pip install wheel
    pip install pyroute2 pyparsing pylibconfig2 m2crypto cryptography
    LINK_TOOLCHAIN="N"

    cd ${OPW}
else
    echo "We can't detect your distro."
    echo "please make sure following development packages are installed to compile smithproxy:"
    echo "   libconfig++-dev"
    echo "   libssl-dev"
    echo "   python-dev"
    echo "   libmicrohttpd-dev"
    echo "   libunwind-dev (version8) iff compiled with -DCMAKE_BUILD_TYPE=Debug"
    echo "   "
    echo "and following packages to make smithproxy infrastructure work:"
    echo "   iptables telnet iproute2 python3 swig"
    echo "   ... python3 packages: pyroute2 pylibconfig2 m2crypto cryptography"

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
