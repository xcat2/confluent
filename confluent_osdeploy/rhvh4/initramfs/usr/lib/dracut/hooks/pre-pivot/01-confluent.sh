#!/bin/bash
BUNDLENAME=/sysroot/etc/pki/tls/certs/ca-bundle.crt
while [ -h $BUNDLENAME ]; do
    BUNDLENAME=/sysroot/$(readlink $BUNDLENAME)
done

cat /etc/pki/tls/certs/ca-bundle.crt > $BUNDLENAME
mkdir -p /sysroot/etc/confluent/
cp -a /tls /sysroot/etc/confluent
sed -i 's/install::/install:*:/' /sysroot/etc/shadow
sed -i 's/root::/root:*:/' /sysroot/etc/shadow
mkdir -p /sysroot/root/.ssh
#chmod 700 /sysroot/root/.ssh
cat /ssh/*.rootpubkey > /sysroot/root/.ssh/authorized_keys
#chmod 600 /sysroot/root/.ssh/authorized_keys
mkdir -p /sysroot/etc/ssh/
for i in /ssh/*.ca; do
    echo '@cert-authority *' $(cat $i) >> /sysroot/etc/ssh/ssh_known_hosts
done
cp /etc/confluent/confluent.apikey /sysroot/etc/
cp /etc/confluent/confluent.apikey /sysroot/etc/confluent/
cp /tmp/confluent.deploycfg /sysroot/etc/
cp /tmp/confluent.deploycfg /sysroot/etc/confluent
cp /opt/confluent/bin/apiclient /sysroot/etc/confluent
cp /tmp/confluent.deploycfg /etc/confluent/* /sysroot/etc/confluent
cp /etc/confluent/confluent.info /sysroot/etc/
