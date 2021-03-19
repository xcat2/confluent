#!/bin/sh

# This script runs when install is finished, but while the installer
# is still running, with the to-be-booted system mounted in /mnt

# carry over deployment configuration and api key for OS install action
mgr=$(grep ^deploy_server /etc/confluent/confluent.deploycfg|awk '{print $2}')
profile=$(grep ^profile: /etc/confluent/confluent.deploycfg|sed -e 's/^profile: //')
nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
export mgr profile nodename
mkdir -p /mnt/etc/confluent
chmod 700 /mnt/etc/confluent
cp /tmp/functions /mnt/etc/confluent/
. /tmp/functions
cp -a /etc/confluent/* /mnt/etc/confluent/
cp -a /tls /mnt/etc/confluent/
cp -a /tls/* /mnt/var/lib/ca-certificates/openssl
cp -a /tls/* /mnt/var/lib/ca-certificates/pem
cp -a /tls/*.pem /mnt/etc/pki/trust/anchors

run_remote setupssh.sh

echo Port 22 >> /etc/ssh/sshd_config
echo Port 2222 >> /etc/ssh/sshd_config
echo Match LocalPort 22 >> /etc/ssh/sshd_config
echo "    ChrootDirectory /mnt" >> /etc/ssh/sshd_config
kill -HUP $(cat /run/sshd.pid)

