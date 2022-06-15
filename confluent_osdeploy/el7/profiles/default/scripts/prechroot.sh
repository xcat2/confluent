#!/bin/sh

# This script runs after install is complete, but inside the installer 
# environment. This is useful for carrying work done in pre/during the
# installer into the installed environment.

# It is almost certainly more useful to use post.sh or firstboot.sh
# for customization, which will run in a more normal mechanism

nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
export confluent_mgr confluent_profile nodename
cp -a /etc/confluent /mnt/sysimage/etc
mkdir -p /mnt/sysimage/opt/confluent/bin
cp /opt/confluent/bin/apiclient /mnt/sysimage/opt/confluent/bin/
chmod -R og-rwx /mnt/sysimage/etc/confluent
cp /tmp/functions /mnt/sysimage/etc/confluent/
hostnamectl set-hostname $nodename
cp /etc/hostname /mnt/sysimage/etc/hostname
. /tmp/functions
if [ -f /tmp/cryptboot ]; then
    cp /tmp/cryptboot /mnt/sysimage/tmp/
fi
mkdir -p /mnt/sysimage/var/log/confluent
mv /tmp/confluent-pre.log /mnt/sysimage/var/log/confluent
echo Port 2222 >> /etc/ssh/sshd_config.anaconda
echo Match LocalPort 22 >> /etc/ssh/sshd_config.anaconda
echo "    ChrootDirectory /mnt/sysimage" >> /etc/ssh/sshd_config.anaconda
kill -HUP $(cat /run/sshd.pid)

# Preserve the ssh setup work done for the installer
# by copying into the target system and setting up
# host based authentication
run_remote setupssh.sh
