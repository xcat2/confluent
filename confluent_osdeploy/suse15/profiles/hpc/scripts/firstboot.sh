#!/bin/sh

# This script runs at the end of the final boot, updating status

nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
mgr=$(grep ^deploy_server /etc/confluent/confluent.deploycfg|awk '{print $2}')
profile=$(grep ^profile: /etc/confluent/confluent.deploycfg|sed -e 's/^rootpassword: //')
proto=$(grep ^protocol: /etc/confluent/confluent.deploycfg |awk '{print $2}')
apikey=$(cat /etc/confluent/confluent.apikey)
curl --capath /etc/confluent/tls -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $apikey" -f -X POST -d "status: complete" https://$mgr/confluent-api/self/updatestatus
