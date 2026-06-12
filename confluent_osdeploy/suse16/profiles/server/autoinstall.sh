#!/bin/bash
serialcons=$(tty)
if [ -e /run/confluent/01-autocons.conf ]; then
    serialcons=$(cat /run/confluent/01-autocons.conf|sed -e s/.*=// -e s/,.*//)
fi
echo "Initializing SSH" > $serialcons
for pubkey in /etc/ssh/ssh_host_*.pub; do
    privfile=${pubkey%.pub}
    certfile=${pubkey/.pub/-cert.pub}
    python3 /opt/confluent/bin/apiclient /confluent-api/self/sshcert $pubkey > $certfile 2> $serialcons
    if [ -s $certfile ]; then
        echo HostCertificate $certfile >> /etc/ssh/sshd_config.d/20_hostkeys.conf
    fi
done
systemctl restart sshd > $serialcons 2>&1
profile=$(grep ^profile: /etc/confluent/confluent.deploycfg|awk '{print $2}')
python3 /opt/confluent/bin/apiclient /confluent-public/os/$profile/autoinstall.json > /tmp/autoinstall.json 2> $serialcons
sed -i s/%%ROOTPASSWORD%%/$(grep ^rootpassword: /etc/confluent/confluent.deploycfg|awk '{print $2}')/g /tmp/autoinstall.json
sed -i s/%%NODENAME%%/$(hostname)/g /tmp/autoinstall.json
python3 /opt/confluent/bin/apiclient /confluent-public/os/$profile/scripts/getinstalldisk > /tmp/getinstalldisk 2> $serialcons
python3 /tmp/getinstalldisk > $serialcons 2>&1
installdisk=$(cat /tmp/getinstalldisk)
if [ -z "$installdisk" ]; then
    echo "Unable to determine target disk for installation" > $serialcons
    sleep inf
fi
echo "Installing to $installdisk" > $serialcons
sed -i 's!%%INSTALLDISK%%!'$installdisk'!g' /tmp/autoinstall.json
locale=$(grep ^locale: /etc/confluent/confluent.deploycfg)
locale=${locale#locale: }
keymap=$(grep ^keymap: /etc/confluent/confluent.deploycfg)
keymap=${keymap#keymap: }
tz=$(grep ^timezone: /etc/confluent/confluent.deploycfg)
tz=${tz#timezone: }
sed -i 's!%%TIMEZONE%%/'$tz'!g' /tmp/autoinstall.json
sed -i s/%%LOCALE%%/$locale/g /tmp/autoinstall.json
sed -i s/%%KEYMAP%%/$keymap/g /tmp/autoinstall.json
agama config load /tmp/autoinstall.json > $serialcons 2>&1

