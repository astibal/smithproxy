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
#    WARNING:
#    Neither this script, nor smithproxy will run wihout ROOT privileges
#


# this is pre-defined defaults. Please don't modify this file, use 
# /etc/defaults/smithproxy to override values from here

# init tenant id

tenant_table="/etc/smithproxy/smithproxy.tenants.cfg"
tenant_id="0"
tenant_index="0"
tenant_range="0.0.0.0/0"


if [[ "$2" != "" ]]; then
    tenant_id="$2"
fi

if [[ "$tenant_id" != "0" ]]; then
    if [[ ! -f "$tenant_table" ]]; then
        echo "ERROR: Tenant table file not found." 
        exit 1
    else 
        L=`cat $tenant_table | grep ";$tenant_id;"`
        if [[ $L  == "" ]]; then
            echo "ERROR: Tenant '$tenant_id' not found in the table."
            exit 1;
        fi
        
        tenant_index=`echo $L | awk -F\; '{ print $1 }'`
        tenant_range=`echo $L | awk -F\; '{ print $3 }'`
        tenant_range6=`echo $L | awk -F\; '{ print $4 }'`
        
        if [[ "$tenant_id" != "" && "$tenant_range" != "" && "$tenant_index" != "" ]]; then
            echo "Tenant: $tenant_id with index $tenant_index ipv4 '$tenant_range' ipv6 '$tenant_range6'"
        else
            echo "ERROR: configuration error in tenant table, tenant $tenant_id"
        fi
    fi
fi

SMITH_CHAIN_NAME="SX.${tenant_id}"
DIVERT_CHAIN_NAME="DX.${tenant_id}"

SMITH_INTERFACE='eth1 eth0'
SMITH_TCP_PORTS='80 25 587 21 143 110 5222 65000'
SMITH_TCP_PORTS_ALL=0
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

# #### DON'T modify anything below, unless you really know what you are doing ####


# source defaults - could be used to override variables above
if [ -f /etc/smithproxy/smithproxy.startup.cfg ]; then
 . /etc/smithproxy/smithproxy.startup.cfg $1 "before"
fi

SMITH_TCP_TPROXY=`expr $SMITH_TCP_TPROXY + $tenant_index`
SMITH_UDP_TPROXY=`expr $SMITH_UDP_TPROXY + $tenant_index`
SMITH_TLS_TPROXY=`expr $SMITH_TLS_TPROXY + $tenant_index`
SMITH_DTLS_TPROXY=`expr $SMITH_DTLS_TPROXY + $tenant_index`
#DIVERT_FWMARK=`expr $DIVERT_FWMARK + $tenant_index`
#DIVERT_IP_RULE=`expr $DIVERT_IP_RULE + $tenant_index`

case "$1" in
  start)
    echo "Smithproxy iptables chains setup script - start tenant: $tenant_id"
    echo 

    echo "Preparing chain ${SMITH_CHAIN_NAME} capturing traffic on ${SMITH_INTERFACE}"

    iptables -t mangle -F ${SMITH_CHAIN_NAME}
    iptables -t mangle -N ${SMITH_CHAIN_NAME}

    ip6tables -t mangle -F ${SMITH_CHAIN_NAME}
    ip6tables -t mangle -N ${SMITH_CHAIN_NAME}    
    
    echo " avoiding tproxy for local traffic"
    for I in `ip a | grep 'inet ' | awk '{ print $2 }' | awk -F/ '{ print $1 }' | grep -v '127\.'`; do
            echo " tproxy exception for ${I}"
            iptables -t mangle -A ${SMITH_CHAIN_NAME} -d ${I} -j ACCEPT
    done
    for I6 in `ip a | grep 'inet6 ' | awk '{ print $2 }' | awk -F/ '{ print $1 }' | grep -v '^::1$'`; do
            echo " tproxy exception for ipv6 ${I6}"
            ip6tables -t mangle -A ${SMITH_CHAIN_NAME} -d ${I6} -j ACCEPT
    done

    
    
    for IF in ${SMITH_INTERFACE}; do
        echo " -- Setting up intercept rules for interface '${IF}'"
    
        echo " tproxy for TCP"
        for P in ${SMITH_TCP_PORTS}; do
            echo "  tproxy port ${IF}/${P}->${SMITH_TCP_TPROXY}"
            iptables -t mangle -A ${SMITH_CHAIN_NAME} -p tcp -i ${IF} --dport ${P} -j TPROXY \
            --tproxy-mark 0x1/0x1 --on-port ${SMITH_TCP_TPROXY}
            ip6tables -t mangle -A ${SMITH_CHAIN_NAME} -p tcp -i ${IF} --dport ${P} -j TPROXY \
            --tproxy-mark 0x1/0x1 --on-port ${SMITH_TCP_TPROXY}
            
        done;
        
        echo " tproxy for UDP"
        for P in ${SMITH_UDP_PORTS}; do
            echo "  tproxy port ${IF}/${P}->${SMITH_UDP_TPROXY}"
            iptables -t mangle -A ${SMITH_CHAIN_NAME} -p udp -i ${IF} --dport ${P} -j TPROXY \
            --tproxy-mark 0x1/0x1 --on-port ${SMITH_UDP_TPROXY}
            ip6tables -t mangle -A ${SMITH_CHAIN_NAME} -p udp -i ${IF} --dport ${P} -j TPROXY \
            --tproxy-mark 0x1/0x1 --on-port ${SMITH_UDP_TPROXY}
        done;
        echo " tproxy for TLS"
        for P in ${SMITH_TLS_PORTS}; do
            echo "  tproxy port ${IF}/${P}->${SMITH_TLS_TPROXY}"
            iptables -t mangle -A ${SMITH_CHAIN_NAME} -p tcp -i ${IF} --dport ${P} -j TPROXY \
            --tproxy-mark 0x1/0x1 --on-port ${SMITH_TLS_TPROXY}
            ip6tables -t mangle -A ${SMITH_CHAIN_NAME} -p tcp -i ${IF} --dport ${P} -j TPROXY \
            --tproxy-mark 0x1/0x1 --on-port ${SMITH_TLS_TPROXY}            
        done;
        echo " tproxy for DTLS"
        for P in ${SMITH_DTLS_PORTS}; do
            echo "  tproxy port ${IF}/${P}->${SMITH_DTLS_TPROXY}"
            iptables -t mangle -A ${SMITH_CHAIN_NAME} -p udp -i ${IF} --dport ${P} -j TPROXY \
            --tproxy-mark 0x1/0x1 --on-port ${SMITH_DTLS_TPROXY}
            ip6tables -t mangle -A ${SMITH_CHAIN_NAME} -p udp -i ${IF} --dport ${P} -j TPROXY \
            --tproxy-mark 0x1/0x1 --on-port ${SMITH_DTLS_TPROXY}
        done;
        echo " drop DTLS ports (until DTLS inspection is implemented)"
        for P in ${TEMP_DTLS_DROP}; do
            echo "  drop port ${IF}/${P}->${TEMP_DTLS_DROP}"
            iptables -t mangle -A ${SMITH_CHAIN_NAME} -p udp -i ${IF} --dport ${P} -j DROP
            ip6tables -t mangle -A ${SMITH_CHAIN_NAME} -p udp -i ${IF} --dport ${P} -j DROP            
        done;
        if [ ${SMITH_TCP_PORTS_ALL} -gt 0 ]; then
            echo " tproxy for all TCP traffic"
            iptables -t mangle -A ${SMITH_CHAIN_NAME} -p tcp -i ${IF} -j TPROXY \
            --tproxy-mark 0x1/0x1 --on-port ${SMITH_TCP_TPROXY}
            ip6tables -t mangle -A ${SMITH_CHAIN_NAME} -p tcp -i ${IF} -j TPROXY \
            --tproxy-mark 0x1/0x1 --on-port ${SMITH_TCP_TPROXY}
        fi
        
        echo " --"
    done
    
    iptables -t mangle -A ${SMITH_CHAIN_NAME} -j RETURN
    ip6tables -t mangle -A ${SMITH_CHAIN_NAME} -j RETURN

    echo " tproxy chain setup finished."
    echo

    echo "Preparing divert chain $DIVERT_CHAIN_NAME"
    iptables -t mangle -F $DIVERT_CHAIN_NAME
    iptables -t mangle -N $DIVERT_CHAIN_NAME
    iptables -t mangle -A $DIVERT_CHAIN_NAME -j MARK --set-mark $DIVERT_FWMARK
    iptables -t mangle -A $DIVERT_CHAIN_NAME -j ACCEPT

    
    ip6tables -t mangle -F $DIVERT_CHAIN_NAME
    ip6tables -t mangle -N $DIVERT_CHAIN_NAME
    ip6tables -t mangle -A $DIVERT_CHAIN_NAME -j MARK --set-mark $DIVERT_FWMARK
    ip6tables -t mangle -A $DIVERT_CHAIN_NAME -j ACCEPT
    
    echo " done"
    echo

    echo "Removing $SMITH_CHAIN_NAME and $DIVERT_CHAIN_NAME references from mangle prerouting"
    iptables -t mangle -L PREROUTING -n -v --line-numbers | egrep "$SMITH_CHAIN_NAME|$DIVERT_CHAIN_NAME" | egrep -o '^[0-9]' | sort -nr | xargs -n1 iptables -t mangle -D PREROUTING
    ip6tables -t mangle -L PREROUTING -n -v --line-numbers | egrep "$SMITH_CHAIN_NAME|$DIVERT_CHAIN_NAME" | egrep -o '^[0-9]' | sort -nr | xargs -n1 iptables -t mangle -D PREROUTING
    echo " done"
    echo

    echo "Applying chains $DIVERT_CHAIN_NAME and $SMITH_CHAIN_NAME into mangle prerouting"
    iptables -t mangle -A PREROUTING -s $tenant_range -p tcp -m socket -j $DIVERT_CHAIN_NAME
    iptables -t mangle -A PREROUTING -s $tenant_range -p udp -m socket -j $DIVERT_CHAIN_NAME
    iptables -t mangle -A PREROUTING -d $tenant_range -p tcp -m socket -j $DIVERT_CHAIN_NAME
    iptables -t mangle -A PREROUTING -d $tenant_range -p udp -m socket -j $DIVERT_CHAIN_NAME

    iptables -t mangle -A PREROUTING -s $tenant_range -j $SMITH_CHAIN_NAME
    iptables -t mangle -A PREROUTING -d $tenant_range -j $SMITH_CHAIN_NAME
    
    
    if [[ "$tenant_range6" != "" ]]; then
        ip6tables -t mangle -A PREROUTING -s $tenant_range6 -p tcp -m socket -j $DIVERT_CHAIN_NAME
        ip6tables -t mangle -A PREROUTING -s $tenant_range6 -p udp -m socket -j $DIVERT_CHAIN_NAME
        ip6tables -t mangle -A PREROUTING -d $tenant_range6 -p tcp -m socket -j $DIVERT_CHAIN_NAME
        ip6tables -t mangle -A PREROUTING -d $tenant_range6 -p udp -m socket -j $DIVERT_CHAIN_NAME

        ip6tables -t mangle -A PREROUTING -s $tenant_range6 -j $SMITH_CHAIN_NAME
        ip6tables -t mangle -A PREROUTING -d $tenant_range6 -j $SMITH_CHAIN_NAME
    fi
    
    echo " done"
    echo

    echo "Applying local lookup for sockets"
    ip rule add fwmark $DIVERT_FWMARK lookup $DIVERT_IP_RULE
    ip route add local 0.0.0.0/0 dev lo table $DIVERT_IP_RULE
    
    ip -6 rule add fwmark $DIVERT_FWMARK lookup $DIVERT_IP_RULE
    ip -6 route add local ::/0 dev lo table $DIVERT_IP_RULE
    
    echo " done"
    echo

    echo "Enabling routing, non-local binds and stack tuning"
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv4.ip_nonlocal_bind=1
    sysctl -w net.ipv4.tcp_low_latency=1
    sysctl -w net.ipv4.tcp_syn_retries=3
    

    sysctl -w net.ipv6.conf.all.forwarding=1
    sysctl -w net.ipv6.ip_nonlocal_bind=1

    echo " done"

    echo "Smithproxy iptables chains setup script - start: finished"
    echo 

    ;;
  stop)
    echo "Smithproxy iptables chains setup script - stop:"
    echo 
    iptables -t mangle -F $DIVERT_CHAIN_NAME
    iptables -t mangle -F $SMITH_CHAIN_NAME

    ip6tables -t mangle -F $DIVERT_CHAIN_NAME
    ip6tables -t mangle -F $SMITH_CHAIN_NAME
    
    echo "Smithproxy iptables chains setup script - stop: finished"
    
    ;;
    
  bypass)
    iptables -t mangle -I $SMITH_CHAIN_NAME 1 -j ACCEPT
    ip6tables -t mangle -I $SMITH_CHAIN_NAME 1 -j ACCEPT
    ;;
  unbypass)
    iptables -t mangle -D $SMITH_CHAIN_NAME -j ACCEPT
    ip6tables -t mangle -D $SMITH_CHAIN_NAME -j ACCEPT
    ;;
    
  *)
    echo "Usage: $0 {start|stop} [tenant ID]"
    exit 1
    ;;
esac


if [ -f /etc/smithproxy/smithproxy.startup.cfg ]; then
 . /etc/smithproxy/smithproxy.startup.cfg $1 "after"
fi