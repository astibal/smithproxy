#!/usr/bin/env bash

OPATH=`pwd`
SXPATH=$1
declare -A components
declare -A versions


SX_LOG="/tmp/sx_log"
SO_LOG="/tmp/so_log"

components[$SX_LOG]="Smithproxy"
components[$SO_LOG]="Socle library"

cd $SXPATH
git log --pretty=format:%s --oneline --output $SX_LOG
versions[$SX_LOG]=`git describe --tags | sed -e 's/-[0-9a-z]*$'//`

cd socle
git log --pretty=format:%s --oneline --output $SO_LOG
versions[$SO_LOG]=`git describe --tags | sed -e 's/-[0-9a-z]*$'//`


echo "smithproxy (${versions[$SX_LOG]}) unstable; urgency=medium"
echo

for f in ${SX_LOG} ${SO_LOG}; do
    echo
    echo "    ${components[$f]}-${versions[$f]}"
    echo
    cat $f | awk '{ print "    * ",$0 }'
done

echo
echo " -- Support <support@smithproxy.org>  `date -R`"
