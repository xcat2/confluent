#!/bin/sh

# This script runs before the installer executes, and sets up ssh during install as well
# as rewriting the autoyast file with any substitutions prior to it being evaluated for real

nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
rootpw=$(grep rootpassword: /etc/confluent/confluent.deploycfg|sed -e 's/^rootpassword: //')
if [ "$rootpw" = "null" ]; then
    rootpw="!"
fi
cryptboot=$(grep encryptboot: /etc/confluent/confluent.deploycfg|sed -e 's/^encryptboot: //')
if [ "$cryptboot" != "" ]  && [ "$cryptboot" != "none" ] && [ "$cryptboot" != "null" ]; then
   echo "****Encrypted boot requested, but not implemented for this OS, halting install" > /dev/console
   [ -f '/tmp/autoconsdev' ] && (echo "****Encryptod boot requested, but not implemented for this OS,halting install" >> $(cat /tmp/autoconsdev))
   while :; do sleep 86400; done
fi

mkdir ~/.ssh
cat /ssh/*.rootpubkey > ~/.ssh/authorized_keys
ssh-keygen -A
for i in  /etc/ssh/ssh_host*key.pub; do
    certname=${i/.pub/-cert.pub}
    curl -f -X POST -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $(cat /etc/confluent/confluent.apikey)" -d @$i https://$mgr/confluent-api/self/sshcert > $certname
    echo HostKey ${i%.pub} >> /etc/ssh/sshd_config
    echo HostCertificate $certname >> /etc/ssh/sshd_config
done
/usr/sbin/sshd
curl -f https://$mgr/confluent-public/os/$profile/scripts/functions > /tmp/functions
. /tmp/functions
run_remote_python getinstalldisk
sed -e s!%%INSTDISK%%!/dev/$(cat /tmp/installdisk)! -e s!%%NODENAME%%!$nodename! -e "s?%%ROOTPASSWORD%%?${rootpw}?" /tmp/profile/autoinst.xml > /tmp/profile/modified.xml
