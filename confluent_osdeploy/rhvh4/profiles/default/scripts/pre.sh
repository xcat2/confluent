#!/bin/sh

# This runs prior to the installer beginning. This is used to rewrite the 
# scripted install file, merging data from confluennt and identifying
# the most appropriate install source.

# If you want to use a more custom partition plan, the easiest
# method is to edit the kicktstart file and comment out or
# delete %include /tmp/partitioning

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
grubpw=$(grep ^grubpassword /etc/confluent.deploycfg | awk '{print $2}')
if [ "$grubpw" = "null" ]; then
    touch /tmp/grubpw
else
    echo "bootloader --iscrypted --password=$grubpw" > /tmp/grubpw
fi
ssh-keygen -A
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
cryptboot=$(grep ^encryptboot: /etc/confluent.deploycfg | awk '{print $2}')
LUKSPARTY=''
if [ "$cryptboot" == "bound" ]; then
	LUKSPARTY="--encrypted --passphrase=$(cat /etc/confluent.apikey)"
	echo $cryptboot >> /tmp/cryptboot
fi


export mgr profile nodename
curl -f https://$mgr/confluent-public/os/$profile/scripts/functions > /tmp/functions
. /tmp/functions
run_remote_python getinstalldisk
if [ -e /tmp/installdisk ]; then
    echo clearpart --all --initlabel >> /tmp/partitioning
    echo ignoredisk --only-use $(cat /tmp/installdisk) >> /tmp/partitioning
    echo autopart --type=thinp --nohome $LUKSPARTY >> /tmp/partitioning
fi
cd $(mktemp -d)
python /etc/confluent/apiclient /confluent-public/os/$profile/image.rpm -o image.rpm
rpm2cpio image.rpm | cpio -dumi
ln -s $(find $(pwd) -name *img) /tmp/install.img
cd -
