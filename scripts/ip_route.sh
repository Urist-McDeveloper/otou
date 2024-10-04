#!/bin/sh

cmd="$1"
server_ip="$2"
tun="$3"
tun_ip="$4"

if [ -z "$cmd" ] || [ -z "$server_ip" ] || [ -z "$tun" ]; then
	echo "usage: $0 <up SERVER_IP TUN TUN_IP>|<down SERVER_IP TUN>" >&2
	exit 1
fi

if [ "$cmd" = "up" ]; then
	set -x
	ip addr add "$tun_ip/24" dev "$tun"
	ip route add blackhole "$server_ip" metric 100
	ip route add "$server_ip" metric 10 via "$(ip route | grep '^default' | cut -d' ' -f3)"
	ip route add 0.0.0.0/1 dev "$tun"
	ip route add 128.0.0.0/1 dev "$tun"
else
	set -x
	ip link del "$tun"
	ip route del "$server_ip" metric 10
	ip route del "$server_ip" metric 100
fi
