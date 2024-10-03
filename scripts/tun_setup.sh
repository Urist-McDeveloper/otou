#!/bin/bash
set -xe

ip link show tun-otou >/dev/null 2>&1 || (
	ip tuntap add mode tun tun-otou
	ip link set mtu 1420 tun-otou
	ip link set multicast off tun-otou
	ip link set up tun-otou
	ip addr add "${1:-10.11.37.1}/24" dev tun-otou
)
