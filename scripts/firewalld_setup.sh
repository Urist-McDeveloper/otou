#!/bin/bash
set -xe

firewall-cmd --version

[ "$(firewall-cmd --permanent --zone=public --get-target)" = "ACCEPT" ] || (
	firewall-cmd --permanent --zone=public --set-target ACCEPT
	firewall-cmd --complete-reload
)

firewall-cmd --set-default-zone public
# equivalent to `iptables -A FORWARD -j ACCEPT`
firewall-cmd --zone=public --add-forward
# equivalent to `iptables -t nat -s 10.13.37.0/24 -A POSTROUTING -j MASQUERADE`
firewall-cmd --zone=public --add-rich-rule='rule family=ipv4 source address=10.13.37.0/24 masquerade'
firewall-cmd --runtime-to-permanent
