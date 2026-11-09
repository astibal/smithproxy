#!/usr/bin/env bash
set -euo pipefail

LAB=${LAB:-/opt/lab/libcli2-demo}
PROXY_NS=${PROXY_NS:-smithproxy-libcli2}
CLIENT_NS=sx-live-client
SERVER_NS=sx-live-server
LIVE_WORKERS=${LIVE_WORKERS:-4}

cleanup() {
    for file in "$LAB"/live/*.pid; do
        [[ -f $file ]] || continue
        kill "$(cat "$file")" 2>/dev/null || true
    done
    ip netns exec "$PROXY_NS" nft delete table ip smithproxy_live 2>/dev/null || true
    ip -n "$PROXY_NS" rule del pref 100 fwmark 1/1 lookup 100 2>/dev/null || true
    ip -n "$PROXY_NS" route del local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
    ip -n "$PROXY_NS" link del sxpxin 2>/dev/null || true
    ip -n "$PROXY_NS" link del sxpxout 2>/dev/null || true
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$SERVER_NS" 2>/dev/null || true
}

if [[ ${1:-} == cleanup ]]; then
    cleanup
    exit
fi

cleanup
mkdir -p "$LAB/live"
ip netns add "$CLIENT_NS"
ip netns add "$SERVER_NS"
ip link add sxcli0 type veth peer name sxpxin
ip link add sxsrv0 type veth peer name sxpxout
ip link set sxcli0 netns "$CLIENT_NS"
ip link set sxpxin netns "$PROXY_NS"
ip link set sxsrv0 netns "$SERVER_NS"
ip link set sxpxout netns "$PROXY_NS"

ip -n "$CLIENT_NS" link set lo up
ip -n "$CLIENT_NS" addr add 198.18.10.2/24 dev sxcli0
ip -n "$CLIENT_NS" link set sxcli0 up
ip -n "$CLIENT_NS" route add default via 198.18.10.1
ip -n "$PROXY_NS" addr add 198.18.10.1/24 dev sxpxin
ip -n "$PROXY_NS" link set sxpxin up
ip -n "$PROXY_NS" addr add 198.18.20.1/24 dev sxpxout
ip -n "$PROXY_NS" link set sxpxout up
ip -n "$SERVER_NS" link set lo up
ip -n "$SERVER_NS" addr add 198.18.20.2/24 dev sxsrv0
ip -n "$SERVER_NS" link set sxsrv0 up
ip -n "$SERVER_NS" route add default via 198.18.20.1

ip netns exec "$PROXY_NS" sysctl -qw net.ipv4.ip_forward=1
for dev in all default sxpxin sxpxout; do
    ip netns exec "$PROXY_NS" sysctl -qw "net.ipv4.conf.$dev.rp_filter=0"
done
ip -n "$PROXY_NS" rule add pref 100 fwmark 1/1 lookup 100
ip -n "$PROXY_NS" route add local 0.0.0.0/0 dev lo table 100
ip netns exec "$PROXY_NS" nft -f - <<'NFT'
table ip smithproxy_live {
    chain forward { type filter hook forward priority filter; policy drop; }
    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        meta l4proto tcp socket transparent 1 counter meta mark set 1 accept
        iifname != "sxpxin" return
        fib daddr type local return
        tcp dport 443 counter tproxy to :50443 meta mark set 1 accept
        udp dport 443 counter tproxy to :50443 meta mark set 1 accept
        meta l4proto tcp counter tproxy to :50080 meta mark set 1 accept
        meta l4proto udp counter tproxy to :50080 meta mark set 1 accept
    }
}
NFT

if [[ ! -s $LAB/live/cert.pem || ! -s $LAB/live/key.pem ]]; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=live.test \
        -keyout "$LAB/live/key.pem" -out "$LAB/live/cert.pem" >/dev/null 2>&1
fi
nohup ip netns exec "$SERVER_NS" python3 -u "$LAB/live/libcli2_live_udp.py" server \
    --transport tcp --port 8080 \
    >"$LAB/live/http.log" 2>&1 & echo $! >"$LAB/live/http.pid"
nohup ip netns exec "$SERVER_NS" python3 -u "$LAB/live/libcli2_live_udp.py" server \
    --transport tls --port 443 --cert "$LAB/live/cert.pem" --key "$LAB/live/key.pem" \
    >"$LAB/live/tls.log" 2>&1 & echo $! >"$LAB/live/tls.pid"
nohup ip netns exec "$SERVER_NS" python3 -u "$LAB/live/libcli2_live_udp.py" server \
    --port 9000 --payload-size 512 \
    >"$LAB/live/udp.log" 2>&1 & echo $! >"$LAB/live/udp.pid"

for worker in $(seq 1 "$LIVE_WORKERS"); do
    nohup ip netns exec "$CLIENT_NS" python3 -u "$LAB/live/libcli2_live_udp.py" client \
        --transport tcp --port 8080 \
        >"$LAB/live/http-client-$worker.log" 2>&1 & echo $! >"$LAB/live/http-client-$worker.pid"
    nohup ip netns exec "$CLIENT_NS" python3 -u "$LAB/live/libcli2_live_udp.py" client \
        --transport tls --port 443 \
        >"$LAB/live/tls-client-$worker.log" 2>&1 & echo $! >"$LAB/live/tls-client-$worker.pid"
    nohup ip netns exec "$CLIENT_NS" python3 -u "$LAB/live/libcli2_live_udp.py" client \
        --port 9000 --payload-size 512 \
        >"$LAB/live/udp-client-$worker.log" 2>&1 & echo $! >"$LAB/live/udp-client-$worker.pid"
done

sleep 2
for file in "$LAB"/live/{http,tls,udp}.pid "$LAB"/live/{http,tls,udp}-client-*.pid; do
    kill -0 "$(cat "$file")"
done
echo "live lab ready: $LIVE_WORKERS HTTP + $LIVE_WORKERS TLS + $LIVE_WORKERS UDP clients"
