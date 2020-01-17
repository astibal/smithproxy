#!/usr/bin/env bash


case "$1" in

start)
    iptables -t nat -F OUTPUT
    # comment out if you want to redirect also for LAN traffic
    iptables -t nat -A OUTPUT -p tcp -d 10.0.0.0/8 -j ACCEPT
    iptables -t nat -A OUTPUT -p tcp -d 172.16.0.0/12 -j ACCEPT
    iptables -t nat -A OUTPUT -p tcp -d 192.168.0.0/16 -j ACCEPT
    # --
    iptables -t nat -A OUTPUT -p tcp -d 127.0.0.0/8 -j ACCEPT
    iptables -t nat -A OUTPUT -p tcp -s 127.0.0.0/8 -j ACCEPT
    iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 51443  -m owner ! --uid-owner root
    iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port 51053  -m owner ! --uid-owner root
    iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-port 51080  -m owner ! --uid-owner root
    ;;

stop)
     iptables -t nat -F OUTPUT
    ;;

esac
