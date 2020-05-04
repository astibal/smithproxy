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

#echo ${OSSTR}
# echo "$OS-$DIST-${REV}_${PSEUDONAME}"
echo "$OS-$DIST-${REV}"

