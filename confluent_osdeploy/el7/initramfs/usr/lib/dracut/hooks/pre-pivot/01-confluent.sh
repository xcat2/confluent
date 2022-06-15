#!/bin/bash
BUNDLENAME=/sysroot/etc/pki/tls/certs/ca-bundle.crt
while [ -h $BUNDLENAME ]; do
    BUNDLENAME=/sysroot/$(readlink $BUNDLENAME)
done

cat /etc/pki/tls/certs/ca-bundle.crt > $BUNDLENAME
mkdir -p /sysroot/etc/confluent/
cp -a /tls /sysroot/etc/confluent
cp -a /etc/confluent/* /sysroot/etc/confluent/
sed -i 's/install::/install:*:/' /sysroot/etc/shadow
sed -i 's/root::/root:*:/' /sysroot/etc/shadow
mkdir -p /sysroot/root/.ssh
#chmod 700 /sysroot/root/.ssh
cat /ssh/*pubkey > /sysroot/root/.ssh/authorized_keys
#chmod 600 /sysroot/root/.ssh/authorized_keys
mkdir -p /sysroot/etc/ssh/
for i in /ssh/*.ca; do
    echo '@cert-authority *' $(cat $i) >> /sysroot/etc/ssh/ssh_known_hosts
done
mkdir -p /sysroot/opt/confluent/bin
cp /opt/confluent/bin/apiclient /sysroot/opt/confluent/bin
cp /opt/confluent/bin/apiclient /sysroot/etc/confluent/
