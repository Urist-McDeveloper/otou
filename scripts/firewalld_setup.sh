#!/bin/bash
set -xe

firewall-cmd --version

[ "$(firewall-cmd --permanent --zone=public --get-target)" = "ACCEPT" ] || (
	firewall-cmd --permanent --zone=public --set-target ACCEPT
	firewall-cmd --complete-reload
)

firewall-cmd --set-default-zone public
firewall-cmd --zone=public --add-forward
firewall-cmd --zone=public --add-rich-rule='rule family=ipv4 source address=10.11.37.0/24 masquerade'
firewall-cmd --runtime-to-permanent
