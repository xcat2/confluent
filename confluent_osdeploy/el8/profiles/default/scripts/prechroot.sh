#!/bin/sh

# This script runs after install is complete, but inside the installer 
# environment. This is useful for carrying work done in pre/during the
# installer into the installed environment.

# It is almost certainly more useful to use post.sh or firstboot.sh
# for customization, which will run in a more normal mechanism

nodename=$(grep ^NODENAME /etc/confluent.info|awk '{print $2}')
export mgr profile nodename
cp -a /etc/confluent /mnt/sysimage/etc
chmod -R og-rwx /mnt/sysimage/etc/confluent
cp /tmp/functions /mnt/sysimage/etc/confluent/
. /tmp/functions
cp /tmp/cryptboot /mnt/sysimage/tmp/

# Preserve the ssh setup work done for the installer
# by copying into the target system and setting up
# host based authentication
run_remote setupssh.sh
