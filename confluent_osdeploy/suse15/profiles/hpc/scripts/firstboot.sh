#!/bin/sh

# This script runs at the end of the final boot, updating status

nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
mgr=$(grep ^deploy_server /etc/confluent/confluent.deploycfg|awk '{print $2}')
profile=$(grep ^profile: /etc/confluent/confluent.deploycfg|sed -e 's/^rootpassword: //')
proto=$(grep ^protocol: /etc/confluent/confluent.deploycfg |awk '{print $2}')
apikey=$(cat /etc/confluent/confluent.apikey)
. /etc/confluent/functions

run_remote firstboot.custom

# Firstboot scripts may be placed into firstboot.d, e.g. firstboot.d/01-firstaction.sh, firstboot.d/02-secondaction.sh
run_remote_parts firstboot

# Induce execution of remote configuration, e.g. ansible plays in ansible/firstboot.d/
run_remote_config firstboot

curl --capath /etc/confluent/tls -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $apikey" -f -X POST -d "status: complete" https://$mgr/confluent-api/self/updatestatus
