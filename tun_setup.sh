#!/bin/bash

if [ -z "$1" ] || [ -z "$2" ]; then
	echo "usage: $0 <tun> <out>" >&2
	exit 3
fi

if [ "$(id -u)" != "0" ]; then
	echo "must run as root" >&2
	exit 2
fi

function set_iptables() {
	iptables $1 -C $2 2>/dev/null
	if [ $? != "0" ]; then
		echo "iptables $1 -A $2"
		iptables $1 -A $2 || exit 1
	fi
}

tun="$1"
out="$2"

echo 1 >/proc/sys/net/ipv4/ip_forward || exit 1

set_iptables "-t nat" "POSTROUTING -o $out -j MASQUERADE --random"
set_iptables "" "FORWARD -i $tun -o $out -j ACCEPT"
set_iptables "" "FORWARD -i $out -o $tun -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
set_iptables "" "FORWARD -j DROP"

ip link show $tun >/dev/null 2>&1
if [ $? != 0 ]; then
	set -xe
	ip tuntap add mode tun $tun
	ip link set multicast off $tun
	ip link set up $tun
	ip addr add 10.11.37.1/24 dev $tun
	set +xe
fi
