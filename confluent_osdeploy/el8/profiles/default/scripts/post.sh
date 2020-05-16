#!/bin/sh
# need to copy over ssh key info
grep HostCert /etc/ssh/sshd_config.anaconda >> /mnt/sysimage/etc/ssh/sshd_config
echo HostbasedAuthentication yes >> /mnt/sysimage/etc/ssh/sshd_config
echo HostbasedUsesNameFromPacketOnly yes >> /mnt/sysimage/etc/ssh/sshd_config
echo IgnoreRhosts no >> /mnt/sysimage/etc/ssh/sshd_config
sshconf=/etc/ssh/ssh_config
if [ -d /mnt/sysimage/etc/ssh/ssh_config.d/ ]; then
    sshconf=/mnt/sysimage/etc/ssh/ssh_config.d/01-confluent.conf
fi
echo 'Host *' >> $sshconf
echo '    HostbasedAuthentication yes' >> $sshconf
echo '    EnableSSHKeysign yes' >> $sshconf
echo '    HostbasedKeyTypes *ed25519*' >> $sshconf

cp /etc/ssh/ssh_host_* /mnt/sysimage/etc/ssh/
mkdir /mnt/sysimage/root/.ssh/
chmod 700 /mnt/sysimage/root/.ssh/
cp /root/.ssh/authorized_keys /mnt/sysimage/root/.ssh/
chmod 600 /mnt/sysimage/root/.ssh/authorized_keys
cp /etc/ssh/ssh_known_hosts /mnt/sysimage/etc/ssh/
cp /tmp/allnodes /mnt/sysimage/etc/ssh/shosts.equiv
cp /tmp/allnodes /mnt/sysimage/root/.shosts
cp -a /etc/confluent /mnt/sysimage/etc
nodename=$(grep ^NODENAME /etc/confluent.info|awk '{print $2}')
curl -f -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $(cat /etc/confluent.apikey)" https://$mgr/confluent-api/self/nodelist > /tmp/allnodes
