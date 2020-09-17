#!/bin/sh

mgr=$(grep ^deploy_server: /etc/confluent/confluent.deploycfg|awk '{print $2}')
profile=$(grep ^profile: /etc/confluent/confluent.deploycfg|awk '{print $2}')
nodename=$(grep ^NODENAME: /etc/confluent/confluent.info|awk '{print $2}')
export mgr profile nodename
curl -sSf https://$mgr/confluent-public/os/$profile/scripts/functions > /tmp/functions
. /tmp/functions

run_remote setupssh.sh

