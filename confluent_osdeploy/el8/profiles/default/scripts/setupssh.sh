#!/bin/sh
targssh=/mnt/sysimage/etc/ssh/sshd_config
if [ -d /mnt/sysimage/etc/ssh/sshd_config.d/ ]; then
	targssh=/mnt/sysimage/etc/ssh/sshd_config.d/90-confluent.conf
fi
grep HostCert /etc/ssh/sshd_config.anaconda >> $targssh
echo HostbasedAuthentication yes >> $targssh
echo HostbasedUsesNameFromPacketOnly yes >> $targssh
echo IgnoreRhosts no >> $targssh
sshconf=/mnt/sysimage/etc/ssh/ssh_config
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
curl -f -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $(cat /etc/confluent/confluent.apikey)" https://$confluent_mgr/confluent-api/self/nodelist > /tmp/allnodes
cp /tmp/allnodes /mnt/sysimage/etc/ssh/shosts.equiv
cp /tmp/allnodes /mnt/sysimage/root/.shosts
