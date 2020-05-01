#!/bin/bash
echo "Confluent first boot is running"
cp -a /etc/confluent/ssh/* /etc/ssh/
systemctl restart sshd
rootpw=$(grep ^rootpassword: /etc/confluent/confluent.deploycfg |awk '{print $2}')
if [ ! -z "$rootpw" -a "$rootpw" != "null" ]; then
	echo root:$rootpw | chpasswd -e
fi
hostnamectl set-hostname $(grep ^NODENAME: /etc/confluent/confluent.info | awk '{print $2}')
