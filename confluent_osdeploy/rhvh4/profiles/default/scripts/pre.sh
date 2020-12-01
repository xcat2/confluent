#!/bin/sh

# This runs prior to the installer beginning. This is used to rewrite the 
# scripted install file, merging data from confluent and identifying
# the most appropriate install source.

# If you want to use a more custom partition plan, the easiest
# method is to edit the kicktstart file and comment out or
# delete %include /tmp/partitioning

mgraw=$(grep ^EXTMGRINFO: /etc/confluent/confluent.info| sed -e 's/^EXTMGRINFO: //' | awk -F'|' '{print $1 " " $2 " " $3}' |grep 1$ | awk 'NR < 2')
if [ -z "$mgraw" ]; then
    mgraw=$(grep ^EXTMGRINFO: /etc/confluent/confluent.info| sed -e 's/^EXTMGRINFO: //' | awk -F'|' '{print $1 " " $2 " " $3}' | awk 'NR < 2')
fi
mgraw=$(echo $mgraw | awk '{print $1}')
if echo $mgraw | grep '%' > /dev/null; then
    echo $mgraw | awk -F% '{print $2}' > /tmp/confluent.ifidx
fi

iface=$(grep -H $(cat /tmp/confluent.ifidx) /sys/class/net/*/ifindex | awk -F/ '{print $5}')
nmcli c u $iface
while ip -6 addr | grep tentative > /dev/null; do
   sleep 0.5
done
nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
locale=$(grep ^locale: /etc/confluent/confluent.deploycfg)
locale=${locale#locale: }
keymap=$(grep ^keymap: /etc/confluent/confluent.deploycfg)
keymap=${keymap#keymap: }
echo lang $locale > /tmp/langinfo
echo keyboard --vckeymap=$keymap >> /tmp/langinfo
tz=$(grep ^timezone: /etc/confluent/confluent.deploycfg)
tz=${tz#timezone: }
ntpsrvs=""
if grep ^ntpservers: /etc/confluent/confluent.deploycfg > /dev/null; then
    ntpsrvs="--ntpservers="$(sed -n '/^ntpservers:/,/^[^-]/p' /etc/confluent/confluent.deploycfg|sed 1d|sed '$d' | sed -e 's/^- //' | paste -sd,)
fi
echo timezone $ntpsrvs $tz --utc > /tmp/timezone
rootpw=$(grep ^rootpassword /etc/confluent/confluent.deploycfg | awk '{print $2}')
if [ "$rootpw" = null ]; then
    echo "rootpw --lock" > /tmp/rootpw
else
    echo "rootpw --iscrypted $rootpw" > /tmp/rootpw
fi
curl -f https://$mgr/confluent-public/os/$profile/profile.yaml > /tmp/instprofile.yaml
blargs=$(grep ^installedargs: /tmp/instprofile.yaml | sed -e 's/#.*//' -e 's/^installedargs: //')
if [ ! -z "$blargs" ]; then
	blargs=' --append="'$blargs'"'
fi
grubpw=$(grep ^grubpassword /etc/confluent/confluent.deploycfg | awk '{print $2}')
if [ "$grubpw" = "null" ]; then
    touch /tmp/grubpw
else
    blargs=" --iscrypted --password=$grubpw $blargs"
fi
if [ ! -z "$blargs" ]; then
    echo "bootloader $blargs" > /tmp/grubpw
fi
ssh-keygen -A
for pubkey in /etc/ssh/ssh_host_*_key.pub; do
    certfile=${pubkey/.pub/-cert.pub}
    curl -f -X POST -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $(cat /etc/confluent/confluent.apikey)" -d @$pubkey https://$mgr/confluent-api/self/sshcert > $certfile
    echo HostCertificate $certfile >> /etc/ssh/sshd_config.anaconda
done
cp /etc/ssh/sshd_config.anaconda /etc/ssh/sshd_config
/usr/sbin/sshd -f /etc/ssh/sshd_config.anaconda
systemctl start sshd
if [ -f "/run/install/cmdline.d/01-autocons.conf" ]; then
    consoledev=$(cat /run/install/cmdline.d/01-autocons.conf | sed -e 's!console=!/dev/!' -e 's/,.*//')
    TMUX= tmux a <> $consoledev >&0 2>&1 &
fi
cryptboot=$(grep ^encryptboot: /etc/confluent/confluent.deploycfg | awk '{print $2}')
LUKSPARTY=''
if [ "$cryptboot" == "tpm2" ]; then
	LUKSPARTY="--encrypted --passphrase=$(cat /etc/confluent/confluent.apikey)"
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
if [ -x /usr/bin/python ]; then
	python=/usr/bin/python
elif [ -x /usr/libexec/platform-python ]; then
	python=/usr/libexec/platform-python
fi
$python /etc/confluent/apiclient /confluent-public/os/$profile/image.rpm -o image.rpm
rpm2cpio image.rpm | cpio -dumi
ln -s $(find $(pwd) -name *img) /tmp/install.img
cd -
$python /etc/confluent/apiclient /confluent-public/os/$profile/kickstart.custom -o /tmp/kickstart.custom
run_remote pre.custom
