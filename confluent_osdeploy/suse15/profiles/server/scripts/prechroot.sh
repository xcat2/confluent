#!/bin/sh

# This script runs when install is finished, but while the installer
# is still running, with the to-be-booted system mounted in /mnt

# carry over deployment configuration and api key for OS install action
confluent_mgr=$(grep ^deploy_server /etc/confluent/confluent.deploycfg|awk '{print $2}')
confluent_profile=$(grep ^profile: /etc/confluent/confluent.deploycfg|sed -e 's/^profile: //')
nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
export confluent_mgr confluent_profile nodename
mkdir -p /mnt/etc/confluent
chmod 700 /mnt/etc/confluent
cp /tmp/functions /mnt/etc/confluent/
. /tmp/functions
cp -a /etc/confluent/* /mnt/etc/confluent/
cp -a /tls /mnt/etc/confluent/
cp -a /tls/* /mnt/var/lib/ca-certificates/openssl
cp -a /tls/* /mnt/var/lib/ca-certificates/pem
cp -a /tls/*.pem /mnt/etc/pki/trust/anchors
cat /tls/*.pem > /mnt/etc/confluent/ca.pem
mkdir -p /mnt/opt/confluent/bin
cp /opt/confluent/bin/apiclient /mnt/opt/confluent/bin/

run_remote setupssh.sh

echo Port 22 >> /etc/ssh/sshd_config
echo Port 2222 >> /etc/ssh/sshd_config
echo Match LocalPort 22 >> /etc/ssh/sshd_config
echo "    ChrootDirectory /mnt" >> /etc/ssh/sshd_config
kill -HUP $(cat /run/sshd.pid)
mkdir -p /mnt/var/log/confluent
cp /tmp/confluent*log /mnt/var/log/confluent

