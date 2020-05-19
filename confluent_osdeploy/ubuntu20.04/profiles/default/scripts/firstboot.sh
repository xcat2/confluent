#!/bin/bash
echo "Confluent first boot is running"
cp -a /etc/confluent/ssh/* /etc/ssh/
systemctl restart sshd
rootpw=$(grep ^rootpassword: /etc/confluent/confluent.deploycfg |awk '{print $2}')
if [ ! -z "$rootpw" -a "$rootpw" != "null" ]; then
	echo root:$rootpw | chpasswd -e
fi
nodename=$(grep ^NODENAME: /etc/confluent/confluent.info | awk '{print $2}')
apikey=$(cat /etc/confluent/confluent.apikey)
mgr=$(grep ^deploy_server: /etc/confluent/confluent.deploycfg |awk '{print $2}')
hostnamectl set-hostname $(grep ^NODENAME: /etc/confluent/confluent.info | awk '{print $2}')
touch /etc/cloud/cloud-init.disabled
curl --capath /etc/confluent/tls -f -X POST -d "status: complete" https://$mgr/confluent-api/self/updatestatus
