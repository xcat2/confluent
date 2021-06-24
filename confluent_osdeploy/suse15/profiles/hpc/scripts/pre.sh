#!/bin/bash

# This script runs before the installer executes, and sets up ssh during install as well
# as rewriting the autoyast file with any substitutions prior to it being evaluated for real

exec >> /tmp/confluent-pre.log
exec 2>> /tmp/confluent-pre.log
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
cat /ssh/*pubkey > ~/.ssh/authorized_keys 2>/dev/null

ssh-keygen -A
for i in  /etc/ssh/ssh_host*key.pub; do
    certname=${i/.pub/-cert.pub}
    curl -f -X POST -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $(cat /etc/confluent/confluent.apikey)" -d @$i https://$confluent_mgr/confluent-api/self/sshcert > $certname
    echo HostKey ${i%.pub} >> /etc/ssh/sshd_config
    echo HostCertificate $certname >> /etc/ssh/sshd_config
done
/usr/sbin/sshd
curl -f https://$confluent_mgr/confluent-public/os/$confluent_profile/scripts/functions > /tmp/functions
. /tmp/functions
ntpcfg=""
if grep ^ntpservers: /etc/confluent/confluent.deploycfg > /dev/null; then
    echo '<ntp-client><ntp_servers config:type="list">' > /tmp/ntp.cfg
    sed -n '/^ntpservers:/,/^[^-]/p' /etc/confluent/confluent.deploycfg | sed 1d|sed '$d'| sed -e 's/^- /<ntp_server><address>/' -e 's!$!</address></ntp_server>!' >> /tmp/ntp.cfg
    echo '</ntp_servers></ntp-client>' >> /tmp/ntp.cfg
    ntpcfg=$(paste -sd '' /tmp/ntp.cfg)
fi
run_remote_python getinstalldisk
sed -e s'!'%%INSTDISK%%'!'/dev/$(cat /tmp/installdisk)'!' -e s'!'%%NODENAME%%'!'$nodename'!' -e s'!<networking>!'$ntpcfg'<networking>!' -e "s?%%ROOTPASSWORD%%?${rootpw}?" /tmp/profile/autoinst.xml > /tmp/profile/modified.xml
if grep append /tmp/bootloader.xml > /dev/null; then
    sed -i 's@</general>@</general>'"$(tr -d '\n' < /tmp/bootloader.xml)"'@' /tmp/profile/modified.xml
fi
sed -i 's#root</username>#root</username>'"$(tr -d '\n' < /tmp/rootkeys.xml)"'#' /tmp/profile/modified.xml
sed -i 's@/hwclock>@/hwclock>'"$(tr -d '\n' < /tmp/timezone)"'@' /tmp/profile/modified.xml
sed -i 's@<media_url/>@'"$(tr -d '\n' < /tmp/pkgurl)"'@' /tmp/profile/modified.xml
