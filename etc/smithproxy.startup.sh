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

#
#    WARNING:
#    Neither this script, nor smithproxy will run without ROOT privileges
#


# /!\  DO NOT EDIT THIS FILE - change variables in smithproxy.startup.cfg /!\

# pre-defined defaults

SMITH_RUN_TRANSPARENT=1     # init transparent
SMITH_RUN_REDIRECT=1        # init redirection
SMITH_RUN_SOCKS=1           # enable socks

SMITH_INTERFACE='-'
SMITH_TCP_PORTS='80 25 587 21 143 110 5222 65000'
SMITH_TCP_PORTS_ALL=1
SMITH_UDP_PORTS_ALL=0
SMITH_IPV6_UDP_BYPASS=0
SMITH_TCP_TPROXY='50080'
SMITH_UDP_PORTS='53'
SMITH_UDP_TPROXY='50080'
SMITH_TLS_PORTS='443 465 636 993 995 10443'
SMITH_TLS_TPROXY='50443'
SMITH_DTLS_PORTS=''
TEMP_DTLS_DROP='443'            # DTLS is being used for example by google, and evades smithproxy if not blocked
SMITH_DTLS_TPROXY='50443'

DIVERT_FWMARK=1
DIVERT_IP_RULE=100

REDIRECT_TLS_PORT='51443'
REDIRECT_TCP_PORT='51080'
REDIRECT_DNS_PORT='51053'
REDIRECT_EXEMPT_LAN=0
REDIRECT_EXEMPT_USERS=""   # could contain multiple users separated by spaces

BYPASS_CONNECTIONS="" # multiple values are semicolon-separated srcip:dstip:dstport tuples

tenant_table="/etc/smithproxy/smithproxy.tenants.cfg"
tenant_id="default"
tenant_index="0"
tenant_range="0.0.0.0/0"
tenant_range6="::/0"


LOGFILE='/var/log/smithproxy/startup.log'


function prepare_log {
  touch ${LOGFILE}
  chmod 600 ${LOGFILE}
}

function logit {
    echo "`date -R`: $1" >> ${LOGFILE}
    echo $1
}

function tenant_apply {

    ACTION=$1

    if [[ "$2" != "" ]]; then
        tenant_id="$2"
    fi


    # set tenant source IP ranges
    if [[ "$tenant_id" != "0" && "$tenant_id" != "default" ]]; then
        if [[ ! -f "${tenant_table}" ]]; then
            logit "ERROR: Tenant table file not found."
            exit 1
        else
            L=`cat ${tenant_table} | grep -v "^#" | grep ";$tenant_id;"`
            if [[ ${L}  == "" ]]; then
                logit "ERROR: Tenant '$tenant_id' not found in the table."
                exit 1;
            fi

            tenant_index=`echo ${L} | awk -F\; '{ print $1 }'`
            tenant_range=`echo ${L} | awk -F\; '{ print $3 }'`
            tenant_range6=`echo ${L} | awk -F\; '{ print $4 }'`

            if [[ "$tenant_id" != "" && "$tenant_range" != "" && "$tenant_index" != "" ]]; then
                logit "Tenant: $tenant_id with index $tenant_index ipv4 '$tenant_range' ipv6 '$tenant_range6'"
            else
                logit "ERROR: configuration error in tenant table, tenant $tenant_id"
            fi
        fi
    fi

    SX_CFG="/etc/smithproxy/smithproxy.cfg"

    if [ -f "/etc/smithproxy/smithproxy.${tenant_id}.cfg" ]; then
        SX_CFG="/etc/smithproxy/smithproxy.${tenant_id}.cfg"
    fi

    if [ `cat ${SX_CFG}  | grep -i accept_tproxy | grep -i false > /dev/null ; echo $?` -eq 0 ]; then
       # we are looking for false, because option can be omitted and default is true
       SMITH_RUN_TRANSPARENT=0
       logit "tproxy disabled in config file"
    fi

    if [ `cat ${SX_CFG}  | grep -i accept_redirect | grep -i false > /dev/null ; echo $?` -eq 0 ]; then
       # we are looking for false, because option can be omitted and default is true
       SMITH_RUN_REDIRECT=0
       logit "redirect disabled in config file"
    fi

    if [ `cat ${SX_CFG}  | grep -i accept_socks | grep -i false > /dev/null ; echo $?` -eq 0 ]; then
       # we are looking for false, because option can be omitted and default is true
       # currently this does nothing
       SMITH_RUN_SOCKS=0
       logit "socks disabled in config file"
    fi

}

function smith_interfaces4 {
    if [[ "${SMITH_INTERFACE}" == '*' ]]; then
        SMITH_INTERFACE=`ip r | grep -o 'dev [a-z0-9]\+' | cut -c5- | sort | uniq | xargs -n1 echo -n "" | cut -c 2-`
        logit " interfaces:auto(*) - enabling on all interfaces ${SMITH_INTERFACE}"

    elif [[ "${SMITH_INTERFACE}" == '-' ]]; then

        # default interfaces grep filter, ie. 'ens1\|ens3'
        DEFI=`ip r | grep '^default' |  grep -o 'dev [a-z0-9]\+' | cut -c5- | sort | uniq | xargs -n1 echo -n "\|" | tr -d ' ' | cut -c3- `
        SMITH_INTERFACE=`ip r | grep -o 'dev [a-z0-9]\+' | cut -c5- | sort | uniq | grep -v "$DEFI" | xargs -n1 echo -n "" | cut -c 2-`

        logit " interfaces:auto(-) - enabling on all downlinks: ${SMITH_INTERFACE}"
    else
       logit " interfaces:manual(${SMITH_INTERFACE})"
    fi
}

function setup_tproxy {


    IPT_CHECK=`iptables -nvL 2>&1`
    IPT_RET=$?
    if [[ $IPT_RET -gt 0 ]]; then
        logit "ERROR: iptables check failed"
        logit "     : ${IPT_CHECK}"

        return
    fi

    SMITH_CHAIN_NAME="SX.${tenant_id}"
    DIVERT_CHAIN_NAME="DX.${tenant_id}"

    SMITH_TCP_TPROXY=`expr ${SMITH_TCP_TPROXY} + ${tenant_index}`
    SMITH_UDP_TPROXY=`expr ${SMITH_UDP_TPROXY} + ${tenant_index}`
    SMITH_TLS_TPROXY=`expr ${SMITH_TLS_TPROXY} + ${tenant_index}`
    SMITH_DTLS_TPROXY=`expr ${SMITH_DTLS_TPROXY} + ${tenant_index}`


    case "$1" in
    start)

        logit "Smithproxy iptables chains setup script - start tenant: $tenant_id"
        logit

        logit "Preparing chain ${SMITH_CHAIN_NAME} capturing traffic on ${SMITH_INTERFACE}"

        iptables -t mangle -F ${SMITH_CHAIN_NAME}
        iptables -t mangle -N ${SMITH_CHAIN_NAME}

        ip6tables -t mangle -F ${SMITH_CHAIN_NAME}
        ip6tables -t mangle -N ${SMITH_CHAIN_NAME}

        logit " avoiding tproxy for local traffic"
        for I in `ip a | grep 'inet ' | awk '{ print $2 }' | awk -F/ '{ print $1 }' | grep -v '^127\.'`; do
                logit " tproxy exception for ${I}"
                iptables -t mangle -A ${SMITH_CHAIN_NAME} -d ${I} -j ACCEPT
        done
        for I6 in `ip a | grep 'inet6 ' | awk '{ print $2 }' | awk -F/ '{ print $1 }' | grep -v '^::1$'`; do
                logit " tproxy exception for ipv6 ${I6}"
                ip6tables -t mangle -A ${SMITH_CHAIN_NAME} -d ${I6} -j ACCEPT
        done

        iptables -t mangle -A ${SMITH_CHAIN_NAME} -d "255.255.255.255" -j ACCEPT
        ip6tables -t mangle -A ${SMITH_CHAIN_NAME} -d "FF00::/8" -j ACCEPT

        smith_interfaces4

        for IF in ${SMITH_INTERFACE}; do

            logit " -- Setting up intercept rules for interface '${IF}'"

            logit " tproxy for TCP"
            for P in ${SMITH_TCP_PORTS}; do
                logit "  tproxy port ${IF}/${P}->${SMITH_TCP_TPROXY}"
                iptables -t mangle -A ${SMITH_CHAIN_NAME} -p tcp -i ${IF} --dport ${P} -j TPROXY \
                --tproxy-mark 0x1/0x1 --on-port ${SMITH_TCP_TPROXY}
                ip6tables -t mangle -A ${SMITH_CHAIN_NAME} -p tcp -i ${IF} --dport ${P} -j TPROXY \
                --tproxy-mark 0x1/0x1 --on-port ${SMITH_TCP_TPROXY}

            done;

            logit " tproxy for UDP"
            for P in ${SMITH_UDP_PORTS}; do
                logit "  tproxy port ${IF}/${P}->${SMITH_UDP_TPROXY}"
                iptables -t mangle -A ${SMITH_CHAIN_NAME} -p udp -i ${IF} --dport ${P} -j TPROXY \
                --tproxy-mark 0x1/0x1 --on-port ${SMITH_UDP_TPROXY}
                ip6tables -t mangle -A ${SMITH_CHAIN_NAME} -p udp -i ${IF} --dport ${P} -j TPROXY \
                --tproxy-mark 0x1/0x1 --on-port ${SMITH_UDP_TPROXY}
            done;
            logit " tproxy for TLS"
            for P in ${SMITH_TLS_PORTS}; do
                logit "  tproxy port ${IF}/${P}->${SMITH_TLS_TPROXY}"
                iptables -t mangle -A ${SMITH_CHAIN_NAME} -p tcp -i ${IF} --dport ${P} -j TPROXY \
                --tproxy-mark 0x1/0x1 --on-port ${SMITH_TLS_TPROXY}

                if [[ ${SMITH_IPV6_UDP_BYPASS} -gt 0 ]]; then
                    logit "  bypassing IPv6 UDP traffic (old kernel?)"
                else
                    ip6tables -t mangle -A ${SMITH_CHAIN_NAME} -p tcp -i ${IF} --dport ${P} -j TPROXY \
                    --tproxy-mark 0x1/0x1 --on-port ${SMITH_TLS_TPROXY}
                fi
            done;
            logit " tproxy for DTLS"
            for P in ${SMITH_DTLS_PORTS}; do
                logit "  tproxy port ${IF}/${P}->${SMITH_DTLS_TPROXY}"
                iptables -t mangle -A ${SMITH_CHAIN_NAME} -p udp -i ${IF} --dport ${P} -j TPROXY \
                --tproxy-mark 0x1/0x1 --on-port ${SMITH_DTLS_TPROXY}
                ip6tables -t mangle -A ${SMITH_CHAIN_NAME} -p udp -i ${IF} --dport ${P} -j TPROXY \
                --tproxy-mark 0x1/0x1 --on-port ${SMITH_DTLS_TPROXY}
            done;
            logit " drop DTLS ports (until DTLS inspection is implemented)"
            for P in ${TEMP_DTLS_DROP}; do
                logit "  drop port ${IF}/${P}->${TEMP_DTLS_DROP}"
                iptables -t mangle -A ${SMITH_CHAIN_NAME} -p udp -i ${IF} --dport ${P} -j DROP
                ip6tables -t mangle -A ${SMITH_CHAIN_NAME} -p udp -i ${IF} --dport ${P} -j DROP
            done;
            if [[ ${SMITH_TCP_PORTS_ALL} -gt 0 ]]; then
                logit " tproxy for all TCP traffic"
                iptables -t mangle -A ${SMITH_CHAIN_NAME} -p tcp -i ${IF} -j TPROXY \
                --tproxy-mark 0x1/0x1 --on-port ${SMITH_TCP_TPROXY}
                ip6tables -t mangle -A ${SMITH_CHAIN_NAME} -p tcp -i ${IF} -j TPROXY \
                --tproxy-mark 0x1/0x1 --on-port ${SMITH_TCP_TPROXY}
            fi
            if [[ ${SMITH_UDP_PORTS_ALL} -gt 0 ]]; then
                logit " tproxy for all TCP traffic"
                iptables -t mangle -A ${SMITH_CHAIN_NAME} -p udp -i ${IF} -j TPROXY \
                --tproxy-mark 0x1/0x1 --on-port ${SMITH_UDP_TPROXY}
                ip6tables -t mangle -A ${SMITH_CHAIN_NAME} -p udp -i ${IF} -j TPROXY \
                --tproxy-mark 0x1/0x1 --on-port ${SMITH_UDP_TPROXY}
            fi


            logit " --"
        done

        iptables -t mangle -A ${SMITH_CHAIN_NAME} -j RETURN
        ip6tables -t mangle -A ${SMITH_CHAIN_NAME} -j RETURN

        logit " tproxy chain setup finished."
        logit

        logit "Preparing divert chain $DIVERT_CHAIN_NAME"
        iptables -t mangle -F ${DIVERT_CHAIN_NAME}
        iptables -t mangle -N ${DIVERT_CHAIN_NAME}
        iptables -t mangle -A ${DIVERT_CHAIN_NAME} -j MARK --set-mark ${DIVERT_FWMARK}
        iptables -t mangle -A ${DIVERT_CHAIN_NAME} -j ACCEPT


        ip6tables -t mangle -F ${DIVERT_CHAIN_NAME}
        ip6tables -t mangle -N ${DIVERT_CHAIN_NAME}
        ip6tables -t mangle -A ${DIVERT_CHAIN_NAME} -j MARK --set-mark ${DIVERT_FWMARK}
        ip6tables -t mangle -A ${DIVERT_CHAIN_NAME} -j ACCEPT

        logit " done"
        logit

        logit "Removing ${SMITH_CHAIN_NAME} and ${DIVERT_CHAIN_NAME} references from mangle prerouting"
        iptables -t mangle -L PREROUTING -n -v --line-numbers | egrep "${SMITH_CHAIN_NAME}" | egrep -o '^[0-9]+' | sort -nr | xargs -n1 iptables -t mangle -D PREROUTING
        iptables -t mangle -L PREROUTING -n -v --line-numbers | egrep "${DIVERT_CHAIN_NAME}" | egrep -o '^[0-9]+' | sort -nr | xargs -n1 iptables -t mangle -D PREROUTING
        ip6tables -t mangle -L PREROUTING -n -v --line-numbers | egrep "${SMITH_CHAIN_NAME}" | egrep -o '^[0-9]+' | sort -nr | xargs -n1 ip6tables -t mangle -D PREROUTING
        ip6tables -t mangle -L PREROUTING -n -v --line-numbers | egrep "${DIVERT_CHAIN_NAME}" | egrep -o '^[0-9]+' | sort -nr | xargs -n1 ip6tables -t mangle -D PREROUTING
        logit " done"
        logit

        logit "Removing old tagged rules"
        iptables -t mangle -L PREROUTING -n -v --line-numbers | egrep "sx_rule" | egrep -o '^[0-9]+' | sort -nr | xargs -n1 iptables -t mangle -D PREROUTING
        ip6tables -t mangle -L PREROUTING -n -v --line-numbers | egrep "sx_rule" | egrep -o '^[0-9]+' | sort -nr | xargs -n1 ip6tables -t mangle -D PREROUTING
        logit " done"


        logit "Applying explicit bypasses"
        for TUPLE in ${BYPASS_CONNECTIONS}; do
            sip=$(echo "${TUPLE}" | awk -F';' '{ print $1 }')
            dip=$(echo "${TUPLE}" | awk -F';' '{ print $2 }')
            dport=$(echo "${TUPLE}" | awk -F';' '{ print $3 }')

            logit "  bypass udp/tcp connections ${sip}->${dip}:${dport}"

            # test if IP is IPv6 or IPv4 by ':' presence (should be enough)
            if [[ $sip == *:* ]]; then
              ip6tables -t mangle -A PREROUTING -p udp -s "${sip}" -d "${dip}" --dport "${dport}" -m comment --comment "sx_rule" -j ACCEPT
              ip6tables -t mangle -A PREROUTING -p udp -s "${dip}" --sport "${dport}" -d "${sip}" -m comment --comment "sx_rule" -j ACCEPT

              ip6tables -t mangle -A PREROUTING -p tcp -s "${sip}" -d "${dip}" --dport "${dport}" -m comment --comment "sx_rule" -j ACCEPT
              ip6tables -t mangle -A PREROUTING -p tcp -s "${dip}" --sport "${dport}" -d "${sip}" -m comment --comment "sx_rule" -j ACCEPT
            else
              iptables -t mangle -A PREROUTING -p udp -s "${sip}" -d "${dip}" --dport "${dport}" -m comment --comment "sx_rule" -j ACCEPT
              iptables -t mangle -A PREROUTING -p udp -s "${dip}" --sport "${dport}" -d "${sip}" -m comment --comment "sx_rule" -j ACCEPT

              iptables -t mangle -A PREROUTING -p tcp -s "${sip}" -d "${dip}" --dport "${dport}" -m comment --comment "sx_rule" -j ACCEPT
              iptables -t mangle -A PREROUTING -p tcp -s "${dip}" --sport "${dport}" -d "${sip}" -m comment --comment "sx_rule" -j ACCEPT
            fi
        done;

        logit "Applying chains $DIVERT_CHAIN_NAME and $SMITH_CHAIN_NAME into mangle prerouting"
        iptables -t mangle -A PREROUTING -s ${tenant_range} -p tcp -m socket -j ${DIVERT_CHAIN_NAME}
        iptables -t mangle -A PREROUTING -s ${tenant_range} -p udp -m socket -j ${DIVERT_CHAIN_NAME}
        iptables -t mangle -A PREROUTING -d ${tenant_range} -p tcp -m socket -j ${DIVERT_CHAIN_NAME}
        iptables -t mangle -A PREROUTING -d ${tenant_range} -p udp -m socket -j ${DIVERT_CHAIN_NAME}

        iptables -t mangle -A PREROUTING -s ${tenant_range} -j ${SMITH_CHAIN_NAME}
        iptables -t mangle -A PREROUTING -d ${tenant_range} -j ${SMITH_CHAIN_NAME}


        if [[ "$tenant_range6" != "" ]]; then
            ip6tables -t mangle -A PREROUTING -s ${tenant_range6} -p tcp -m socket -j ${DIVERT_CHAIN_NAME}
            ip6tables -t mangle -A PREROUTING -s ${tenant_range6} -p udp -m socket -j ${DIVERT_CHAIN_NAME}
            ip6tables -t mangle -A PREROUTING -d ${tenant_range6} -p tcp -m socket -j ${DIVERT_CHAIN_NAME}
            ip6tables -t mangle -A PREROUTING -d ${tenant_range6} -p udp -m socket -j ${DIVERT_CHAIN_NAME}

            ip6tables -t mangle -A PREROUTING -s ${tenant_range6} -j ${SMITH_CHAIN_NAME}
            ip6tables -t mangle -A PREROUTING -d ${tenant_range6} -j ${SMITH_CHAIN_NAME}
        fi

        logit " done"
        logit

        logit "Applying local lookup for sockets"
        ip rule add fwmark ${DIVERT_FWMARK} lookup ${DIVERT_IP_RULE}
        ip route add local 0.0.0.0/0 dev lo table ${DIVERT_IP_RULE}

        ip -6 rule add fwmark ${DIVERT_FWMARK} lookup ${DIVERT_IP_RULE}
        ip -6 route add local ::/0 dev lo table ${DIVERT_IP_RULE}

        logit " done"
        logit

        logit "Enabling routing, non-local binds and stack tuning"
        sysctl -w net.ipv4.ip_forward=1
        sysctl -w net.ipv4.ip_nonlocal_bind=1
        sysctl -w net.ipv4.tcp_low_latency=1
        sysctl -w net.ipv4.tcp_syn_retries=3


        sysctl -w net.ipv6.conf.all.forwarding=1
        sysctl -w net.ipv6.ip_nonlocal_bind=1

        logit " done"

        logit "Smithproxy iptables chains setup script - start: finished"
        logit

        ;;

    stop)

        logit "Smithproxy iptables chains setup script - stop:"
        logit

        logit "Removing ${SMITH_CHAIN_NAME} and ${DIVERT_CHAIN_NAME} references from mangle prerouting"
        iptables -t mangle -L PREROUTING -n -v --line-numbers | egrep "${SMITH_CHAIN_NAME}" | egrep -o '^[0-9]+' | sort -nr | xargs -n1 iptables -t mangle -D PREROUTING
        iptables -t mangle -L PREROUTING -n -v --line-numbers | egrep "${DIVERT_CHAIN_NAME}" | egrep -o '^[0-9]+' | sort -nr | xargs -n1 iptables -t mangle -D PREROUTING
        ip6tables -t mangle -L PREROUTING -n -v --line-numbers | egrep "${SMITH_CHAIN_NAME}" | egrep -o '^[0-9]+' | sort -nr | xargs -n1 ip6tables -t mangle -D PREROUTING
        ip6tables -t mangle -L PREROUTING -n -v --line-numbers | egrep "${DIVERT_CHAIN_NAME}" | egrep -o '^[0-9]+' | sort -nr | xargs -n1 ip6tables -t mangle -D PREROUTING
        logit " done"

        logit "Removing tagged rules"
        iptables -t mangle -L PREROUTING -n -v --line-numbers | egrep "sx_rule" | egrep -o '^[0-9]+' | sort -nr | xargs -n1 iptables -t mangle -D PREROUTING
        ip6tables -t mangle -L PREROUTING -n -v --line-numbers | egrep "sx_rule" | egrep -o '^[0-9]+' | sort -nr | xargs -n1 ip6tables -t mangle -D PREROUTING
        logit " done"

        logit


        iptables -t mangle -F ${DIVERT_CHAIN_NAME}
        iptables -t mangle -F ${SMITH_CHAIN_NAME}
        iptables -t mangle -X ${DIVERT_CHAIN_NAME}
        iptables -t mangle -X ${SMITH_CHAIN_NAME}

        ip6tables -t mangle -F ${DIVERT_CHAIN_NAME}
        ip6tables -t mangle -F ${SMITH_CHAIN_NAME}
        ip6tables -t mangle -X ${DIVERT_CHAIN_NAME}
        ip6tables -t mangle -X ${SMITH_CHAIN_NAME}

        logit "Smithproxy iptables chains setup script - stop: finished"

        ;;

    bypass)

        iptables -t mangle -I ${SMITH_CHAIN_NAME} 1 -j ACCEPT
        ip6tables -t mangle -I ${SMITH_CHAIN_NAME} 1 -j ACCEPT
        ;;

    unbypass)

        iptables -t mangle -D ${SMITH_CHAIN_NAME} -j ACCEPT
        ip6tables -t mangle -D ${SMITH_CHAIN_NAME} -j ACCEPT
        ;;

    *)
        logit "setup_tproxy: $0 {start|stop} [tenant ID]"
        exit 1
        ;;
    esac
}


function setup_redirect {

    SMITH_CHAIN_NAME="SX.rdr.${tenant_id}"

    IPT_CHECK=`iptables -nvL 2>&1`
    IPT_RET=$?
    if [[ $IPT_RET -gt 0 ]]; then
        logit "ERROR: iptables check failed"
        logit "     : ${IPT_CHECK}"

        return
    fi


    case "$1" in

    start|unbypass)

        iptables -t nat -F ${SMITH_CHAIN_NAME}
        iptables -t nat -N ${SMITH_CHAIN_NAME}

        ip6tables -t nat -F ${SMITH_CHAIN_NAME}
        ip6tables -t nat -N ${SMITH_CHAIN_NAME}


        if [[ ${REDIRECT_EXEMPT_LAN} -gt 0 ]]; then
            iptables -t nat -A ${SMITH_CHAIN_NAME} -p tcp -d 10.0.0.0/8 -j ACCEPT
            iptables -t nat -A ${SMITH_CHAIN_NAME} -p tcp -d 172.16.0.0/12 -j ACCEPT
            iptables -t nat -A ${SMITH_CHAIN_NAME} -p tcp -d 192.168.0.0/16 -j ACCEPT

            ip6tables -t nat -A ${SMITH_CHAIN_NAME} -p tcp -d fe80::/10 -j ACCEPT
        fi

        # don't loop yourself
        iptables -t nat -A ${SMITH_CHAIN_NAME} -p tcp -d 127.0.0.0/8 -j ACCEPT
        iptables -t nat -A ${SMITH_CHAIN_NAME} -p tcp -s 127.0.0.0/8 -j ACCEPT

        ip6tables -t nat -A ${SMITH_CHAIN_NAME} -p tcp -d ::1 -j ACCEPT
        ip6tables -t nat -A ${SMITH_CHAIN_NAME} -p tcp -s ::1 -j ACCEPT

        if [ "${REDIRECT_EXEMPT_USERS}" != "" ]; then
            for U in ${REDIRECT_EXEMPT_USERS}; do
                iptables -t nat -A ${SMITH_CHAIN_NAME} -m owner --uid-owner `id -u ${U}` -j ACCEPT
                ip6tables -t nat -A ${SMITH_CHAIN_NAME} -m owner --uid-owner `id -u ${U}` -j ACCEPT
            done
        fi


        # this piece of ... code is here because some really tight environments don't return ID or arbitrary user (and root)
        ROOT_ID="0"
        ROOT_MAPPED=`( id -u root ) > /dev/null 2>&1`
        if [ "$?" != "0" ]; then
            echo " ... assuming root id is 0";
        else
            ROOT_ID=`id -u root`
            if [ "$?" != "0" ]; then
                # if even that doesn't work assume 0
                ROOT_ID="0"
            fi
        fi

        for P in ${SMITH_TLS_PORTS}; do
            logit "  redirect port ${P}->${SMITH_TLS_TPROXY}"
            iptables -t nat -A ${SMITH_CHAIN_NAME} -p tcp --dport ${P} -j REDIRECT --to-port ${REDIRECT_TLS_PORT}  -m owner ! --uid-owner ${ROOT_ID}
            ip6tables -t nat -A ${SMITH_CHAIN_NAME} -p tcp --dport ${P} -j REDIRECT --to-port ${REDIRECT_TLS_PORT}  -m owner ! --uid-owner ${ROOT_ID}
        done;

        for P in ${SMITH_TCP_PORTS}; do
            logit "  redirect port ${P}->${SMITH_TCP_TPROXY}"
            iptables -t nat -A ${SMITH_CHAIN_NAME} -p tcp --dport ${P} -j REDIRECT --to-port ${REDIRECT_TCP_PORT}  -m owner ! --uid-owner ${ROOT_ID}
            ip6tables -t nat -A ${SMITH_CHAIN_NAME} -p tcp --dport ${P} -j REDIRECT --to-port ${REDIRECT_TCP_PORT}  -m owner ! --uid-owner ${ROOT_ID}
        done;

        if [[ ${SMITH_TCP_PORTS_ALL} -gt 0 ]]; then
            logit "  redirect ALL tcp->${SMITH_TCP_TPROXY}"
            iptables -t nat -A ${SMITH_CHAIN_NAME} -p tcp -j REDIRECT --to-port ${REDIRECT_TCP_PORT} -m owner ! --uid-owner ${ROOT_ID}
            ip6tables -t nat -A ${SMITH_CHAIN_NAME} -p tcp -j REDIRECT --to-port ${REDIRECT_TCP_PORT} -m owner ! --uid-owner ${ROOT_ID}
        fi

        if [[ ${SMITH_UDP_PORTS_ALL} -gt 0 ]]; then
            logit "  redirecting ALL udp-> *ignored for redirect*"
        fi

        iptables -t nat -A ${SMITH_CHAIN_NAME} -p udp --dport 53 -j REDIRECT --to-port ${REDIRECT_DNS_PORT}  -m owner ! --uid-owner ${ROOT_ID}
        ip6tables -t nat -A ${SMITH_CHAIN_NAME} -p udp --dport 53 -j REDIRECT --to-port ${REDIRECT_DNS_PORT}  -m owner ! --uid-owner ${ROOT_ID}


        iptables -t nat -A ${SMITH_CHAIN_NAME} -j RETURN

        logit "Removing ${SMITH_CHAIN_NAME} references from nat output"
        iptables -t nat -L OUTPUT -n -v --line-numbers | egrep "${SMITH_CHAIN_NAME}" | egrep -o '^[0-9]+' | sort -nr | xargs -n1 iptables -t nat -D OUTPUT
        ip6tables -t nat -L OUTPUT -n -v --line-numbers | egrep "${SMITH_CHAIN_NAME}" | egrep -o '^[0-9]+' | sort -nr | xargs -n1 ip6tables -t nat -D OUTPUT


        iptables -t nat -A OUTPUT -j ${SMITH_CHAIN_NAME}
        ip6tables -t nat -A OUTPUT -j ${SMITH_CHAIN_NAME}

        ;;

    stop|bypass)
        logit "Removing ${SMITH_CHAIN_NAME} references from nat output"
        iptables -t nat -L OUTPUT -n -v --line-numbers | egrep "${SMITH_CHAIN_NAME}" | egrep -o '^[0-9]+' | sort -nr | xargs -n1 iptables -t nat -D OUTPUT
        ip6tables -t nat -L OUTPUT -n -v --line-numbers | egrep "${SMITH_CHAIN_NAME}" | egrep -o '^[0-9]+' | sort -nr | xargs -n1 ip6tables -t nat -D OUTPUT

        iptables -t nat -F ${SMITH_CHAIN_NAME}
        ip6tables -t nat -F ${SMITH_CHAIN_NAME}

        iptables -t nat -X ${SMITH_CHAIN_NAME}
        ip6tables -t nat -X ${SMITH_CHAIN_NAME}
        ;;

    esac

}


prepare_log

tenant_apply $1 $2


# #### DON'T modify anything below, unless you really know what you are doing ####


# source defaults - could be used to override variables above
if [[ -f /etc/smithproxy/smithproxy.startup.cfg ]]; then
 . /etc/smithproxy/smithproxy.startup.cfg $1 "before"
fi

case "$1" in

    stop|bypass)
      setup_tproxy $1
      setup_redirect $1

      ;;

    start|unbypass)
    if [[ ${SMITH_RUN_TRANSPARENT} -gt 0 ]]; then
        setup_tproxy $1
    fi

    if [[ ${SMITH_RUN_REDIRECT} -gt 0 ]]; then
        setup_redirect $1
    fi

    ;;

  *)
    logit "Usage: $0 {start|stop} [tenant ID]"
    exit 1
    ;;
esac


if [[ -f /etc/smithproxy/smithproxy.startup.cfg ]]; then
 . /etc/smithproxy/smithproxy.startup.cfg $1 "after"
fi