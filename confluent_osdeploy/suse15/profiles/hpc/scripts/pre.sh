#!/bin/sh

# This script runs before the installer executes, and sets up ssh during install as well
# as rewriting the autoyast file with any substitutions prior to it being evaluated for real

nodename=$(grep ^NODENAME /tmp/confluent.info|awk '{print $2}')
rootpw=$(grep rootpassword: /tmp/confluent.deploycfg|sed -e 's/^rootpassword: //')
if [ "$rootpw" = "null" ]; then
    rootpw="!"
fi

mkdir ~/.ssh
cat /ssh/*.rootpubkey > ~/.ssh/authorized_keys
ssh-keygen -A
for i in  /etc/ssh/ssh_host*key.pub; do
    certname=${i/.pub/-cert.pub}
    curl -f -X POST -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $(cat /tmp/confluent.apikey)" -d @$i https://$mgr/confluent-api/self/sshcert > $certname
    echo HostKey ${i%.pub} >> /etc/ssh/sshd_config
    echo HostCertificate $certname >> /etc/ssh/sshd_config
done
/usr/sbin/sshd
curl -f ${proto}://$mgr/confluent-public/confluent/util/getinstalldisk > /tmp/getinstalldisk
python3 /tmp/getinstalldisk
sed -e s!%%INSTDISK%%!/dev/$(cat /tmp/installdisk)! -e s!%%NODENAME%%!$nodename! -e "s?%%ROOTPASSWORD%%?${rootpw}?" /tmp/profile/autoinst.xml > /tmp/profile/modified.xml
