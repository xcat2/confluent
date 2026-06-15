#!/bin/sh

# This script runs when install is finished, but while the installer
# is still running, with the to-be-booted system mounted in /mnt

# carry over deployment configuration and api key for OS install action

confluent_profile=$(grep ^profile: /etc/confluent/confluent.deploycfg|sed -e 's/^profile: //')
nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
export confluent_profile nodename
mkdir -p /mnt/etc/confluent
chmod 700 /mnt/etc/confluent
cp /etc/confluent/functions /mnt/etc/confluent/
. /etc/confluent/functions
cp -a /etc/confluent/* /mnt/etc/confluent/
cp -a /etc/confluent/tls/* /mnt/var/lib/ca-certificates/openssl
cp -a /etc/confluent/tls/* /mnt/var/lib/ca-certificates/pem
cp -a /etc/confluent/tls/*.pem /mnt/etc/pki/trust/anchors
cat /etc/confluent/tls/*.pem > /mnt/etc/confluent/ca.pem
mkdir -p /mnt/opt/confluent/bin
cp /opt/confluent/bin/apiclient /mnt/opt/confluent/bin/

#run_remote setupssh.sh
cp /etc/ssh/ssh*key* /mnt/etc/ssh/
mkdir -p /mnt/etc/ssh/sshd_config.d/
cp /etc/ssh/sshd_config.d/20_hostkeys.conf /mnt/etc/ssh/sshd_config.d/
mkdir -p /mnt/root/.ssh/
cp /root/.ssh/authorized_keys /mnt/root/.ssh/

echo Port 22 >> /etc/ssh/sshd_config.d/00-chroot.conf
echo Port 2222 >> /etc/ssh/sshd_config.d/00-chroot.conf
echo Match LocalPort 22 >> /etc/ssh/sshd_config.d/00-chroot.conf
echo "    ChrootDirectory /mnt" >> /etc/ssh/sshd_config.d/00-chroot.conf
systemctl restart sshd
mkdir -p /mnt/var/log/confluent
cp /tmp/confluent*log /mnt/var/log/confluent

