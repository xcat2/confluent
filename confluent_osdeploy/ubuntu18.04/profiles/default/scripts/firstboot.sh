#!/bin/bash
echo "Confluent first boot is running"
#cp -a /etc/confluent/ssh/* /etc/ssh/
#systemctl restart sshd
rootpw=$(grep ^rootpassword: /etc/confluent/confluent.deploycfg |awk '{print $2}')
if [ ! -z "$rootpw" -a "$rootpw" != "null" ]; then
	echo root:$rootpw | chpasswd -e
fi
nodename=$(grep ^NODENAME: /etc/confluent/confluent.info | awk '{print $2}')
confluent_apikey=$(cat /etc/confluent/confluent.apikey)
confluent_mgr=$(grep ^deploy_server: /etc/confluent/confluent.deploycfg |awk '{print $2}')
while ! ping -c 1 $confluent_mgr >& /dev/null; do
	sleep 1
done
source /etc/confluent/functions

run_remote_parts firstboot.d
run_remote_config firstboot.d
systemctl disable firstboot
curl -f -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $confluent_apikey" -X POST -d "status: complete" https://$confluent_mgr/confluent-api/self/updatestatus
