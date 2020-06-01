#!/bin/sh

# This script runs when install is finished, but while the installer
# is still running, with the to-be-booted system mounted in /mnt

# carry over deployment configuration and api key for OS install action
mgr=$(grep ^deploy_server /tmp/confluent.deploycfg|awk '{print $2}')
profile=$(grep ^profile: /tmp/confluent.deploycfg|sed -e 's/^profile: //')
nodename=$(grep ^NODENAME /tmp/confluent.info|awk '{print $2}')
export mgr profile nodename
mkdir -p /mnt/etc/confluent
chmod 700 /mnt/etc/confluent
chmod 600 /tmp/confluent.*
cp /tmp/functions /mnt/etc/confluent/
. /tmp/functions
cp /tmp/confluent.* /mnt/etc/confluent/
cp -a /tls /mnt/etc/confluent/
cp -a /tls/* /mnt/var/lib/ca-certificates/openssl
cp -a /tls/* /mnt/var/lib/ca-certificates/pem
cp -a /tls/*.pem /mnt/etc/pki/trust/anchors

run_remote setupssh.sh
