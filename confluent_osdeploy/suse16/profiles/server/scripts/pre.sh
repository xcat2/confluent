#!/bin/bash

# This script runs before the installer executes, and sets up ssh during install as well
# as rewriting the autoyast file with any substitutions prior to it being evaluated for real

exec >> /tmp/confluent-pre.log
exec 2>> /tmp/confluent-pre.log
chmod 600 /tmp/confluent-pre.log
cryptboot=$(grep encryptboot: /etc/confluent/confluent.deploycfg|sed -e 's/^encryptboot: //')
if [ "$cryptboot" != "" ]  && [ "$cryptboot" != "none" ] && [ "$cryptboot" != "null" ]; then
   echo "****Encrypted boot requested, but not implemented for this OS, halting install"
   while :; do sleep 86400; done
fi
echo "Initializing SSH"
for pubkey in /etc/ssh/ssh_host_*key.pub; do
    privfile=${pubkey%.pub}
    certfile=${pubkey/.pub/-cert.pub}
    python3 /opt/confluent/bin/apiclient /confluent-api/self/sshcert $pubkey > $certfile
    if [ -s $certfile ]; then
        echo HostCertificate $certfile >> /etc/ssh/sshd_config.d/20_hostkeys.conf
    fi
done
systemctl restart sshd
python3 /opt/confluent/bin/apiclient /confluent-public/os/$profile/autoinstall.json > /tmp/autoinstall.json
deployserver=$(grep ^deploy_server: /etc/confluent/confluent.deploycfg|awk '{print $2}')
if [ -z "$deployserver" ] || [ "$deployserver" = "none" ] || [ "$deployserver" = "null" ]; then
    deployserver=$(grep ^deploy_server_v6: /etc/confluent/confluent.deploycfg|awk '{print $2}')
fi
if [[ "$deployserver" == *":"* ]]; then
    deployserver="[$deployserver]"
fi
source /etc/confluent/functions
run_remote_parts pre.d
sed -i s!%%DEPLOYER%%!$deployserver!g /tmp/autoinstall.json
sed -i s!%%PROFILE%%!$(grep ^profile: /etc/confluent/confluent.deploycfg|awk '{print $2}')!g /tmp/autoinstall.json
sed -i s!%%ROOTPASSWORD%%!$(grep ^rootpassword: /etc/confluent/confluent.deploycfg|awk '{print $2}')!g /tmp/autoinstall.json
sed -i s!%%NODENAME%%!$(hostname)!g /tmp/autoinstall.json
python3 /opt/confluent/bin/apiclient /confluent-public/os/$profile/scripts/getinstalldisk > /tmp/getinstalldisk
locale=$(grep ^locale: /etc/confluent/confluent.deploycfg)
locale=${locale#locale: }
keymap=$(grep ^keymap: /etc/confluent/confluent.deploycfg)
keymap=${keymap#keymap: }
tz=$(grep ^timezone: /etc/confluent/confluent.deploycfg)
tz=${tz#timezone: }
sed -i 's!%%TIMEZONE%%!'$tz'!g' /tmp/autoinstall.json
sed -i 's!%%LOCALE%%!'$locale'!g' /tmp/autoinstall.json
sed -i 's!%%KEYMAP%%!'$keymap'!g' /tmp/autoinstall.json
if [ ! -e /tmp/installdisk ]; then
    python3 /tmp/getinstalldisk
fi
installdisk=$(cat /tmp/installdisk)
if [ -z "$installdisk" ]; then
    echo "Unable to determine target disk for installation"
    sleep inf
fi
echo "Installing to $installdisk"
sed -i 's!%%INSTALLDISK%%!'/dev/$installdisk'!g' /tmp/autoinstall.json