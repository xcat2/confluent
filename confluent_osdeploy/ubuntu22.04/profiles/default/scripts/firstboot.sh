#!/bin/bash
echo "Confluent first boot is running"
HOME=$(getent passwd $(whoami)|cut -d: -f 6)
export HOME
(
exec >> /var/log/confluent/confluent-firstboot.log
exec 2>> /var/log/confluent/confluent-firstboot.log
chmod 600 /var/log/confluent/confluent-firstboot.log
cp -a /etc/confluent/ssh/* /etc/ssh/
systemctl restart ssh
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
hostnamectl set-hostname $(grep ^NODENAME: /etc/confluent/confluent.info | awk '{print $2}')
touch /etc/cloud/cloud-init.disabled
source /etc/confluent/functions
confluent_profile=$(grep ^profile: /etc/confluent/confluent.deploycfg|awk '{print $2}')
export confluent_mgr confluent_profile
run_remote_parts firstboot.d
run_remote_config firstboot.d
curl --capath /etc/confluent/tls -f -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $confluent_apikey" -X POST -d "status: complete" https://$confluent_mgr/confluent-api/self/updatestatus
) &
tail --pid $! -n 0 -F /var/log/confluent/confluent-post.log > /dev/console
