#!/bin/bash
cat /tls/*.pem >> /var/lib/ca-certificates/ca-bundle.pem
rm /etc/cmdline.d/10-liveroot.conf
if ! grep -q console= /proc/cmdline; then
	autocons=$(/opt/confluent/bin/autocons)
	if [ -n "$autocons" ]; then
		echo console=$autocons | sed -e 's!/dev/!!' .> /tmp/01-autocons.conf
		autocons=${autocons%,*}
		echo $autocons > /tmp/01-autocons.devnode
		echo Detected text console at $(cat /tmp/01-autocons.conf) > $autocons
	fi
fi
if grep -q console=ttyS /proc/cmdline; then
	echo "Serial console requested in kernel command line, local video may not show progress" > /dev/tty1
fi
mkdir -p /run/NetworkManager/initrd /etc/cmdline.d
if ! grep -q rd.neednet /proc/cmdline; then
	echo rd.neednet >> /etc/cmdline.d/01-confluent.conf
fi
: > /run/NetworkManager/initrd/neednet
