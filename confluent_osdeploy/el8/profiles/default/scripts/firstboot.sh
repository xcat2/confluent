#!/bin/sh
nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
apikey=$(cat /etc/confluent/confluent.apikey)
mgr=$(grep mgt_server /etc/confluent/confluent.deploycfg|awk '{print $2}')
curl --capath /etc/confluent/tls -X POST -d 'status: complete' -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $apikey" https://$mgr/confluent-api/self/updatestatus
systemctl disable firstboot
rm /etc/systemd/system/firstboot.service
