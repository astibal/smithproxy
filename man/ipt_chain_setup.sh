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
    
    


SMITH_CHAIN_NAME='SMITH'
SMITH_INTERFACE='eth1'
SMITH_TCP_PORTS='80 25 587 21 143 110 5222'
SMITH_TCP_TPROXY='50080'
SMITH_UDP_PORTS='53'
SMITH_UDP_TPROXY='50081'
SMITH_TLS_PORTS='443 465 636 993 995'
SMITH_TLS_TPROXY='50443'
SMITH_DTLS_PORS=''
SMITH_DTLS_TPROXY='50444'

echo "Smithproxy tproxy chain setup script."
echo "Preparing chain ${SMITH_CHAIN_NAME} capturing traffic on ${SMITH_INTERFACE}"

iptables -t mangle -F ${SMITH_CHAIN_NAME}
iptables -t mangle -N ${SMITH_CHAIN_NAME}

echo "tproxy for TCP"
for P in ${SMITH_TCP_PORTS}; do
    echo "tproxy port ${SMITH_INTERFACE}/${P}->${SMITH_TCP_TPROXY}"
    iptables -t mangle -A ${SMITH_CHAIN_NAME} -p tcp -i ${SMITH_INTERFACE} --dport ${P} -j TPROXY \
    --tproxy-mark 0x1/0x1 --on-port ${SMITH_TCP_TPROXY}
done;
echo "tproxy for UDP"
for P in ${SMITH_UDP_PORTS}; do
    echo "tproxy port ${SMITH_INTERFACE}/${P}->${SMITH_UDP_TPROXY}"
    iptables -t mangle -A ${SMITH_CHAIN_NAME} -p udp -i ${SMITH_INTERFACE} --dport ${P} -j TPROXY \
    --tproxy-mark 0x1/0x1 --on-port ${SMITH_UDP_TPROXY}
done;
echo "tproxy for TLS"
for P in ${SMITH_TLS_PORTS}; do
    echo "tproxy port ${SMITH_INTERFACE}/${P}->${SMITH_TLS_TPROXY}"
    iptables -t mangle -A ${SMITH_CHAIN_NAME} -p tcp -i ${SMITH_INTERFACE} --dport ${P} -j TPROXY \
    --tproxy-mark 0x1/0x1 --on-port ${SMITH_TLS_TPROXY}
done;
echo "tproxy for DTLS"
for P in ${SMITH_DTLS_PORTS}; do
    echo "tproxy port ${SMITH_INTERFACE}/${P}->${SMITH_DTLS_TPROXY}"
    iptables -t mangle -A ${SMITH_CHAIN_NAME} -p tcp -i ${SMITH_INTERFACE} --dport ${P} -j TPROXY \
    --tproxy-mark 0x1/0x1 --on-port ${SMITH_DTLS_TPROXY}
done;

echo 
echo "tproxy chain setup finished."
