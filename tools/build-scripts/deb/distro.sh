#!/bin/sh
# Detects which OS and if it is Linux then it will detect which Linux Distribution.

OS=`uname -s`
REV=`uname -r`
MACH=`uname -m`

GetVersionFromFile()
{
	VERSION=`cat $1 | tr "\n" ' ' | sed s/.*VERSION.*=\ // `
}

if [ "${OS}" = "SunOS" ] ; then
	OS=Solaris
	ARCH=`uname -p`	
	OSSTR="${OS} ${REV}(${ARCH} `uname -v`)"
elif [ "${OS}" = "AIX" ] ; then
	OSSTR="${OS} `oslevel` (`oslevel -r`)"
elif [ "${OS}" = "Linux" ] ; then
	KERNEL=`uname -r`
	if [ -f /etc/redhat-release ] ; then
		DIST='RedHat'
		PSUEDONAME=`cat /etc/redhat-release | sed s/.*\(// | sed s/\)//`
		REV=`cat /etc/redhat-release | sed s/.*release\ // | sed s/\ .*//`
	elif [ -f /etc/SUSE-release ] ; then
		DIST=`cat /etc/SUSE-release | tr "\n" ' '| sed s/VERSION.*//`
		REV=`cat /etc/SUSE-release | tr "\n" ' ' | sed s/.*=\ //`
	elif [ -f /etc/mandrake-release ] ; then
		DIST='Mandrake'
		PSUEDONAME=`cat /etc/mandrake-release | sed s/.*\(// | sed s/\)//`
		REV=`cat /etc/mandrake-release | sed s/.*release\ // | sed s/\ .*//`
	elif [ -f /etc/lsb-release ] ; then
		eval `cat /etc/lsb-release`
		DIST=$DISTRIB_ID
		PSEUDONAME=$DISTRIB_CODENAME
		REV=$DISTRIB_RELEASE
	elif [ -f /etc/debian_version ] ; then
		DIST="Debian"
		REV="`cat /etc/debian_version | awk -F"/" '{ print $1 }'`"
	fi


	if [ -f /etc/UnitedLinux-release ] ; then
		DIST="${DIST}[`cat /etc/UnitedLinux-release | tr "\n" ' ' | sed s/VERSION.*//`]"
	fi
	
	OSSTR="${OS} ${DIST} ${REV}(${PSUEDONAME} ${KERNEL} ${MACH})"

fi

#echo ${OSSTR}
# echo "$OS-$DIST-${REV}_${PSEUDONAME}"
echo "$OS-$DIST-${REV}"

