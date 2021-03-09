#!/bin/bash
BUNDLENAME=/sysroot/etc/pki/tls/certs/ca-bundle.crt
while [ -h $BUNDLENAME ]; do
    BUNDLENAME=/sysroot/$(readlink $BUNDLENAME)
done
cat /tls/*.0 >> $BUNDLENAME
mkdir -p /sysroot/etc/confluent/
chmod 700 /sysroot/etc/confluent
cp -a /tls /sysroot/etc/confluent
cp /etc/confluent/* /sysroot/etc/confluent
rootpw=$(grep ^rootpassword: /etc/confluent/confluent.deploycfg | awk '{print $2}')
if [ "null" = "$rootpw" -o "" = $rootpw ]; then
        rootpw='*'
fi
sed -i "s!root:[^:]*:!root:$rootpw:!" /sysroot/etc/shadow
mkdir -p /sysroot/root/.ssh
chmod 700 /sysroot/root/.ssh
cat /ssh/*pubkey > /sysroot/root/.ssh/authorized_keys
chmod 600 /sysroot/root/.ssh/authorized_keys
mkdir -p /sysroot/etc/ssh/
for i in /ssh/*.ca; do
    echo '@cert-authority *' $(cat $i) >> /sysroot/etc/ssh/ssh_known_hosts
done
cp /opt/confluent/bin/apiclient /sysroot/etc/confluent
cp /etc/sysconfig/network-scripts/* /sysroot/etc/sysconfig/network-scripts/
ifname=$(ip link|grep ^$(cat /tmp/confluent.ifidx) | awk '{print $2}'|sed -e 's/://')
mkdir /sysroot/tmp
ip link set $ifname down; ip link set $ifname up
while ! ip addr show dev $ifname|grep fe80 > /dev/null; do
        sleep 0.1
done
while ip addr|grep tentative > /dev/null; do
        sleep 0.1
done
mgr=$(grep ^deploy_server: /etc/confluent/confluent.deploycfg|awk '{print $2}')
profile=$(grep ^profile: /etc/confluent/confluent.deploycfg|awk '{print $2}')
export mgr profile
curl -Ssf https://$mgr/confluent-public/os/$profile/scripts/earlyboot.sh > /sysroot/etc/confluent/earlyboot.sh
chroot /sysroot bash /etc/confluent/earlyboot.sh

