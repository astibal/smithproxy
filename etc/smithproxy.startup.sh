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

SMITH_CHAIN_NAME='SMITH'
DIVERT_CHAIN_NAME='DIVERT'

SMITH_INTERFACE='eth1'
SMITH_TCP_PORTS='80 25 587 21 143 110 5222'
SMITH_TCP_PORTS_ALL=0
SMITH_TCP_TPROXY='50080'
SMITH_UDP_PORTS='53'
SMITH_UDP_TPROXY='50081'
SMITH_TLS_PORTS='443 465 636 993 995 10443'
SMITH_TLS_TPROXY='50443'
SMITH_DTLS_PORTS=''
TEMP_DTLS_DROP='443'            # DTLS is being used for example by google, and evades smithproxy if not blocked
SMITH_DTLS_TPROXY='50444'

DIVERT_FWMARK=1
DIVERT_IP_RULE=100

# #### DON'T modify anything below, unless you really know what you are doing ####


# source defaults - could be used to override variables above
if [ -f /etc/smithproxy/smithproxy.startup.cfg ]; then
 . /etc/smithproxy/smithproxy.startup.cfg $1 "before"
fi

case "$1" in
  start)
    echo "Smithproxy iptables chains setup script - start:"
    echo 

    echo "Preparing chain ${SMITH_CHAIN_NAME} capturing traffic on ${SMITH_INTERFACE}"

    iptables -t mangle -F ${SMITH_CHAIN_NAME}
    iptables -t mangle -N ${SMITH_CHAIN_NAME}

    echo " avoiding tproxy for local traffic"
    for I in `ip a | grep 'inet ' | awk '{ print $2 }' | awk -F/ '{ print $1 }' | grep -v '127\.'`; do
            echo " tproxy exception for ${I}"
            iptables -t mangle -A ${SMITH_CHAIN_NAME} -d ${I} -j ACCEPT
    done

    echo " tproxy for TCP"
    for P in ${SMITH_TCP_PORTS}; do
        echo "  tproxy port ${SMITH_INTERFACE}/${P}->${SMITH_TCP_TPROXY}"
        iptables -t mangle -A ${SMITH_CHAIN_NAME} -p tcp -i ${SMITH_INTERFACE} --dport ${P} -j TPROXY \
        --tproxy-mark 0x1/0x1 --on-port ${SMITH_TCP_TPROXY}
    done;
    if [[ SMITH_TCP_PORTS_ALL > 0 ]]; then
        echo " tproxy for all TCP traffic"
        iptables -t mangle -A ${SMITH_CHAIN_NAME} -p tcp -i ${SMITH_INTERFACE} -j TPROXY \
        --tproxy-mark 0x1/0x1 --on-port ${SMITH_TCP_TPROXY}
    fi
    
    echo " tproxy for UDP"
    for P in ${SMITH_UDP_PORTS}; do
        echo "  tproxy port ${SMITH_INTERFACE}/${P}->${SMITH_UDP_TPROXY}"
        iptables -t mangle -A ${SMITH_CHAIN_NAME} -p udp -i ${SMITH_INTERFACE} --dport ${P} -j TPROXY \
        --tproxy-mark 0x1/0x1 --on-port ${SMITH_UDP_TPROXY}
    done;
    echo " tproxy for TLS"
    for P in ${SMITH_TLS_PORTS}; do
        echo "  tproxy port ${SMITH_INTERFACE}/${P}->${SMITH_TLS_TPROXY}"
        iptables -t mangle -A ${SMITH_CHAIN_NAME} -p tcp -i ${SMITH_INTERFACE} --dport ${P} -j TPROXY \
        --tproxy-mark 0x1/0x1 --on-port ${SMITH_TLS_TPROXY}
    done;
    echo " tproxy for DTLS"
    for P in ${SMITH_DTLS_PORTS}; do
        echo "  tproxy port ${SMITH_INTERFACE}/${P}->${SMITH_DTLS_TPROXY}"
        iptables -t mangle -A ${SMITH_CHAIN_NAME} -p udp -i ${SMITH_INTERFACE} --dport ${P} -j TPROXY \
        --tproxy-mark 0x1/0x1 --on-port ${SMITH_DTLS_TPROXY}
    done;
    echo " drop DTLS ports (until DTLS inspection is implemented)"
    for P in ${TEMP_DTLS_DROP}; do
        echo "  drop port ${SMITH_INTERFACE}/${P}->${TEMP_DTLS_DROP}"
        iptables -t mangle -A ${SMITH_CHAIN_NAME} -p udp -i ${SMITH_INTERFACE} --dport ${P} -j DROP
    done;
    
    iptables -t mangle -A ${SMITH_CHAIN_NAME} -j RETURN

    echo " tproxy chain setup finished."
    echo

    echo "Preparing divert chain $DIVERT_CHAIN_NAME"
    iptables -t mangle -F $DIVERT_CHAIN_NAME
    iptables -t mangle -N $DIVERT_CHAIN_NAME
    iptables -t mangle -A $DIVERT_CHAIN_NAME -j MARK --set-mark $DIVERT_FWMARK
    iptables -t mangle -A $DIVERT_CHAIN_NAME -j ACCEPT
    echo " done"
    echo

    echo "Removing $SMITH_CHAIN_NAME and $DIVERT_CHAIN_NAME references from mangle prerouting"
    iptables -t mangle -L PREROUTING -n -v --line-numbers | egrep "$SMITH_CHAIN_NAME|$DIVERT_CHAIN_NAME" | egrep -o '^[0-9]' | sort -nr | xargs -n1 iptables -t mangle -D PREROUTING
    echo " done"
    echo

    echo "Applying chains $DIVERT_CHAIN_NAME and $SMITH_CHAIN_NAME into mangle prerouting"
    iptables -t mangle -A PREROUTING -p tcp -m socket -j $DIVERT_CHAIN_NAME
    iptables -t mangle -A PREROUTING -p udp -m socket -j $DIVERT_CHAIN_NAME
    iptables -t mangle -A PREROUTING -j $SMITH_CHAIN_NAME
    echo " done"
    echo

    echo "Applying local lookup for sockets"
    ip rule add fwmark $DIVERT_FWMARK lookup $DIVERT_IP_RULE
    ip route add local 0.0.0.0/0 dev lo table $DIVERT_IP_RULE
    echo " done"
    echo

    echo "Enabling routing and non-local binds"
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv4.ip_nonlocal_bind=1
    echo " done"

    echo "Smithproxy iptables chains setup script - start: finished"
    echo 

    ;;
  stop)
    echo "Smithproxy iptables chains setup script - stop:"
    echo 
    iptables -t mangle -F $DIVERT_CHAIN_NAME
    iptables -t mangle -F $SMITH_CHAIN_NAME
    
    echo "Smithproxy iptables chains setup script - stop: finished"
    
    ;;
  *)
    echo "Usage: $0 {start|stop}"
    exit 1
    ;;
esac


if [ -f /etc/smithproxy/smithproxy.startup.cfg ]; then
 . /etc/smithproxy/smithproxy.startup.cfg $1 "after"
fi