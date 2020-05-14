#!/bin/sh
nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
mgr=$(grep ^ipv._server /etc/confluent/confluent.deploycfg|awk '{print $2}')
profile=$(grep ^profile: /etc/confluent/confluent.deploycfg|sed -e 's/^rootpassword: //')
proto=$(grep ^protocol: /etc/confluent/confluent.deploycfg |awk '{print $2}')
apikey=$(cat /etc/confluent/confluent.apikey)
