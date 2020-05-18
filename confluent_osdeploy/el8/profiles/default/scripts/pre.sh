#!/bin/sh
nodename=$(grep ^NODENAME /etc/confluent.info|awk '{print $2}')
locale=$(grep ^locale: /etc/confluent.deploycfg)
locale=${locale#locale: }
keymap=$(grep ^keymap: /etc/confluent.deploycfg)
keymap=${keymap#keymap: }
echo lang $locale > /tmp/langinfo
echo keyboard --vckeymap=$keymap >> /tmp/langinfo
tz=$(grep ^timezone: /etc/confluent.deploycfg)
tz=${tz#timezone: }
echo timezone $tz --utc > /tmp/timezone
rootpw=$(grep ^rootpassword /etc/confluent.deploycfg | awk '{print $2}')
if [ "$rootpw" = null ]; then
    echo "rootpw --lock" > /tmp/rootpw
else
    echo "rootpw --iscrypted $rootpw" > /tmp/rootpw
fi
for pubkey in /etc/ssh/ssh_host*key.pub; do
    certfile=${pubkey/.pub/-cert.pub}
    curl -f -X POST -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $(cat /etc/confluent.apikey)" -d @$pubkey https://$mgr/confluent-api/self/sshcert > $certfile
    echo HostCertificate $certfile >> /etc/ssh/sshd_config.anaconda
done
/usr/sbin/sshd -f /etc/ssh/sshd_config.anaconda
if [ -f "/run/install/cmdline.d/01-autocons.conf" ]; then
    consoledev=$(cat /run/install/cmdline.d/01-autocons.conf | sed -e 's!console=!/dev/!' -e 's/,.*//')
    tmux a <> $consoledev >&0 2>&1 &
fi
curl https://$mgr/confluent-public/confluent/util/getinstalldisk > /tmp/getinstalldisk
/usr/libexec/platform-python /tmp/getinstalldisk
if [ -e /tmp/installdisk ]; then
    echo clearpart --all --initlabel >> /tmp/partitioning
    echo ignoredisk --only-use $(cat /tmp/installdisk) >> /tmp/partitioning
    echo autopart --nohome >> /tmp/partitioning
fi
