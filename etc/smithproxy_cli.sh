#!/bin/bash

#
#     Smithproxy- transparent proxy with SSL inspection capabilities.
#     Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.
#
#     Smithproxy is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, either version 3 of the License, or
#     (at your option) any later version.
#
#     Smithproxy is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with Smithproxy.  If not, see <http://www.gnu.org/licenses/>.
#
#    In addition, as a special exception, the copyright holders of Smithproxy
#    give you permission to combine Smithproxy with free software programs
#    or libraries that are released under the GNU LGPL and with code
#    included in the standard release of OpenSSL under the OpenSSL's license
#    (or modified versions of such code, with unchanged license).
#    You may copy and distribute such a system following the terms
#    of the GNU GPL for Smithproxy and the licenses of the other code
#    concerned, provided that you include the source code of that other code
#    when and as the GNU GPL requires distribution of source code.
#
#    Note that people who make modified versions of Smithproxy are not
#    obligated to grant this special exception for their modified versions;
#    it is their choice whether to do so. The GNU General Public License
#    gives permission to release a modified version without this exception;
#    this exception also makes it possible to release a modified version
#    which carries forward this exception.
#    In addition, as a special exception, the copyright holders of Smithproxy
#    give you permission to combine Smithproxy with free software programs
#    or libraries that are released under the GNU LGPL and with code
#    included in the standard release of OpenSSL under the OpenSSL's license
#    (or modified versions of such code, with unchanged license).
#    You may copy and distribute such a system following the terms
#    of the GNU GPL for Smithproxy and the licenses of the other code
#    concerned, provided that you include the source code of that other code
#    when and as the GNU GPL requires distribution of source code.
#
#    Note that people who make modified versions of Smithproxy are not
#    obligated to grant this special exception for their modified versions;
#    it is their choice whether to do so. The GNU General Public License
#    gives permission to release a modified version without this exception;
#    this exception also makes it possible to release a modified version
#    which carries forward this exception.

num_re='^[0-9]+$'
DEFAULT_PORT="50000"
ARCHIVE="${SMITHPROXY_CFTAR:-/etc/smithproxy/smithproxy.cftar}"
CFTAR="${SMITHPROXY_CFTAR_CMD:-smithproxy-cftar}"
TEMP_CONFIG=""

cleanup() {
    [ -z "${TEMP_CONFIG}" ] || rm -f "${TEMP_CONFIG}"
}
trap cleanup EXIT HUP INT TERM

# The standalone configuration is native-only. An absent archive means the
# daemon has not completed its one-time migration and the CLI must not revive
# a stale loose configuration behind it. Tenant files remain an explicit,
# separate legacy feature until tenant support is redesigned.
if [ ! -f "${ARCHIVE}" ]; then
    echo "Native Smithproxy configuration is unavailable: ${ARCHIVE}" >&2
    exit 1
fi
TEMP_CONFIG="$(mktemp)" || exit 1
"${CFTAR}" get "${ARCHIVE}" smithproxy.cfg >"${TEMP_CONFIG}" || exit 1
CONFIG="${TEMP_CONFIG}"

PORT=$(grep 'cli \+= *\|port *=' "${CONFIG}" | grep 'cli \+= *' -A1 | grep port | awk -F= '{ print $2 }' | grep -o '[0-9]\+')

if [ -f /etc/smithproxy/smithproxy.tenants.cfg ]; then

    if [ "$1" != "" ]; then

        if [ -f /etc/smithproxy/smithproxy.${1}.cfg ]; then
            PORT=`cat /etc/smithproxy/smithproxy.${1}.cfg | grep 'cli \+= *\|port *=' | grep 'cli \+= *' -A1 | grep port | awk -F= '{ print $2 }' |  grep -o '[0-9]\+'`
        fi

        PORT_INDEX=`cat /etc/smithproxy/smithproxy.tenants.cfg | grep -v '^ *#' | grep "; *$1 *;" | awk -F";" '{ print $1 }' `
        PORT=`expr $PORT + $PORT_INDEX`
        
        echo "port: $PORT"
        
        if ! [[ $PORT =~ $num_re ]] ; then
            echo "Cannot determine tenant port!" >&2; exit 1
        fi
        
    else
        echo "Specify one of tenant names as the argument: "
        cat /etc/smithproxy/smithproxy.tenants.cfg | grep -v '^ *#' | awk -F";" '{ print $2 }'
        echo
        echo
        exit
    fi
fi

if [ "$PORT" != "" ]; then
   telnet localhost $PORT
else
   echo
   echo "WARNING: cannot obtain CLI port! Trying default $DEFAULT_PORT"
   echo
   telnet localhost $DEFAULT_PORT
fi
echo "Terminated."
