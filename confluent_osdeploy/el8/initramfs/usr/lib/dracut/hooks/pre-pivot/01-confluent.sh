#!/bin/bash
BUNDLENAME=/sysroot/etc/pki/tls/certs/ca-bundle.crt
if [ ! -e "$BUNDLENAME" ]; then
    BUNDLENAME=/sysroot/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
fi
while [ -h $BUNDLENAME ]; do
    BUNDLENAME=/sysroot/$(readlink $BUNDLENAME)
done

cat /etc/pki/tls/certs/ca-bundle.crt > $BUNDLENAME
mkdir -p /sysroot/etc/confluent/
chmod 700 /sysroot/etc/confluent
cp -a /tls /sysroot/etc/confluent
cp /etc/confluent/* /sysroot/etc/confluent
sed -i 's/install::/install:*:/' /sysroot/etc/shadow
sed -i 's/root::/root:*:/' /sysroot/etc/shadow
mkdir -p /sysroot/root/.ssh
chmod 700 /sysroot/root/.ssh
cat /ssh/*pubkey > /sysroot/root/.ssh/authorized_keys
chmod 600 /sysroot/root/.ssh/authorized_keys
mkdir -p /sysroot/etc/ssh/
for i in /ssh/*.ca; do
    echo '@cert-authority *' $(cat $i) >> /sysroot/etc/ssh/ssh_known_hosts
done
mkdir -p /sysroot/opt/confluent/bin
cp /opt/confluent/bin/apiclient /sysroot/opt/confluent/bin
cp /opt/confluent/bin/apiclient /sysroot/etc/confluent/
