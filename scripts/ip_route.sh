#!/bin/sh

if [ "$1" = "up" ]; then
	set -x
	ip route add 0.0.0.0/1 dev tun-otou
	ip route add 128.0.0.0/1 dev tun-otou
else
	set -x
	ip route del 0.0.0.0/1
	ip route del 128.0.0.0/1
fi
