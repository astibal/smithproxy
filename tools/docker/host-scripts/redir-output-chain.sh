#!/usr/bin/env bash

# taken shamelessly from smithproxy.startup.cfg
SMITH_TLS_PORTS='443 465 636 993 995 10443'

EXEMPT_USERS="root fahclient boinc"

case "$1" in

start)
    iptables -t nat -F OUTPUT
    ip6tables -t nat -F OUTPUT

    # comment out if you want to redirect also for LAN traffic
    iptables -t nat -A OUTPUT -p tcp -d 10.0.0.0/8 -j ACCEPT
    iptables -t nat -A OUTPUT -p tcp -d 172.16.0.0/12 -j ACCEPT
    iptables -t nat -A OUTPUT -p tcp -d 192.168.0.0/16 -j ACCEPT
    # --
    iptables -t nat -A OUTPUT -p tcp -d 127.0.0.0/8 -j ACCEPT
    iptables -t nat -A OUTPUT -p tcp -s 127.0.0.0/8 -j ACCEPT


    ip6tables -t nat -A OUTPUT -p tcp -d ::1 -j ACCEPT
    ip6tables -t nat -A OUTPUT -p tcp -s ::1 -j ACCEPT

    ip6tables -t nat -A OUTPUT -p tcp -d fe80::/10 -j ACCEPT


    for U in $EXEMPT_USERS; do
        iptables -t nat -A OUTPUT -m owner --uid-owner `id -u ${U}` -j ACCEPT
        ip6tables -t nat -A OUTPUT -m owner --uid-owner `id -u ${U}` -j ACCEPT
    done

    for P in $SMITH_TLS_PORTS; do
        iptables -t nat -A OUTPUT -p tcp --dport ${P} -j REDIRECT --to-port 51443  -m owner ! --uid-owner `id -u root`
        ip6tables -t nat -A OUTPUT -p tcp --dport ${P} -j REDIRECT --to-port 51443  -m owner ! --uid-owner `id -u root`
    done;

    iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port 51053  -m owner ! --uid-owner `id -u root`
    iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-port 51080  -m owner ! --uid-owner `id -u root`

    #ip6tables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port 51053  -m owner ! --uid-owner `id -u root`
    ip6tables -t nat -A OUTPUT -p tcp -j REDIRECT --to-port 51080  -m owner ! --uid-owner `id -u root`

    ;;

stop)
     iptables -t nat -F OUTPUT
    ;;

esac
