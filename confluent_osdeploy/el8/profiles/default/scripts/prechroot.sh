#!/bin/sh
# need to copy over ssh key info
nodename=$(grep ^NODENAME /etc/confluent.info|awk '{print $2}')
export mgr profile nodename
cp -a /etc/confluent /mnt/sysimage/etc
curl -f https://$mgr/confluent-public/os/$profile/scripts/functions > /tmp/functions
. /tmp/functions
run_remote setupssh.sh
