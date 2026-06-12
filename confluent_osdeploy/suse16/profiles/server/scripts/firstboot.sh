#!/bin/bash
HOME=$(getent passwd $(whoami)|cut -d: -f 6)
export HOME

# This script runs at the end of the final boot, updating status
exec >> /var/log/confluent/confluent-firstboot.log
exec 2>> /var/log/confluent/confluent-firstboot.log
chmod 600 /var/log/confluent/confluent-firstboot.log

nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
v6cfg=$(grep ^ipv6_method: /etc/confluent/confluent.deploycfg)
v6cfg=${v6cfg#ipv6_method: }
if [ "$v6cfg" = "static" ]; then
    confluent_mgr=$(grep ^deploy_server_v6: /etc/confluent/confluent.deploycfg)
    confluent_mgr=${confluent_mgr#deploy_server_v6: }
    confluent_mgr="[$confluent_mgr]"
else
    confluent_mgr=$(grep ^deploy_server: /etc/confluent/confluent.deploycfg)
    confluent_mgr=${confluent_mgr#deploy_server: }
fi
confluent_profile=$(grep ^profile: /etc/confluent/confluent.deploycfg|sed -e 's/^profile: //')
proto=$(grep ^protocol: /etc/confluent/confluent.deploycfg |awk '{print $2}')
confluent_apikey=$(cat /etc/confluent/confluent.apikey)
. /etc/confluent/functions
GIVUP=$(($(date +%s) + 60))
while (! ping -c 1 $confluent_mgr >& /dev/null) && [ $(date +%s) -lt $GIVUP ]; do
	sleep 1
done

for i in  /etc/ssh/ssh_host*key.pub; do
    certname=${i/.pub/-cert.pub}
    curl -f -X POST -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $(cat /etc/confluent/confluent.apikey)" -d @$i https://$confluent_mgr/confluent-api/self/sshcert > $certname
done
systemctl restart sshd
run_remote_python confignet
run_remote firstboot.custom

# Firstboot scripts may be placed into firstboot.d, e.g. firstboot.d/01-firstaction.sh, firstboot.d/02-secondaction.sh
run_remote_parts firstboot.d

# Induce execution of remote configuration, e.g. ansible plays in ansible/firstboot.d/
run_remote_config firstboot.d

curl --capath /etc/confluent/tls -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $confluent_apikey" -f -X POST -d "status: complete" https://$confluent_mgr/confluent-api/self/updatestatus
