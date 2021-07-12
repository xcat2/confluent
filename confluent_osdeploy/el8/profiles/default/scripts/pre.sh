#!/bin/sh

# This runs prior to the installer beginning. This is used to rewrite the 
# scripted install file, merging data from confluent and identifying
# the most appropriate install source.

# If you want to use a more custom partition plan, the easiest
# method is to edit the kicktstart file and comment out or
# delete %include /tmp/partitioning
if [ -f "/run/install/cmdline.d/01-autocons.conf" ]; then
    consoledev=$(cat /run/install/cmdline.d/01-autocons.conf | sed -e 's!console=!/dev/!' -e 's/,.*//')
    TMUX= tmux a <> $consoledev >&0 2>&1 &
fi
exec >> /tmp/confluent-pre.log
exec 2>> /tmp/confluent-pre.log
tail -f /tmp/confluent-pre.log > /dev/tty &
logshowpid=$!
/usr/libexec/platform-python /etc/confluent/apiclient >& /dev/null
nicname=$(ip link|grep ^$(cat /tmp/confluent.ifidx): | awk '{print $2}' | awk -F: '{print $1}')
nmcli c u $nicname
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
curl -sf https://$confluent_mgr/confluent-public/os/$confluent_profile/profile.yaml > /tmp/instprofile.yaml
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
for pubkey in /etc/ssh/ssh_host*key.pub; do
    certfile=${pubkey/.pub/-cert.pub}
    curl -sf -X POST -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $(cat /etc/confluent/confluent.apikey)" -d @$pubkey https://$confluent_mgr/confluent-api/self/sshcert > $certfile
    echo HostCertificate $certfile >> /etc/ssh/sshd_config.anaconda
done
/usr/sbin/sshd -f /etc/ssh/sshd_config.anaconda
cryptboot=$(grep ^encryptboot: /etc/confluent/confluent.deploycfg | awk '{print $2}')
LUKSPARTY=''
touch /tmp/cryptpkglist
touch /tmp/addonpackages
if [ "$cryptboot" == "tpm2" ]; then
	LUKSPARTY="--encrypted --passphrase=$(cat /etc/confluent/confluent.apikey)"
	echo $cryptboot >> /tmp/cryptboot
    echo clevis-dracut >> /tmp/cryptpkglist
fi


export confluent_mgr confluent_profile nodename
curl -sf https://$confluent_mgr/confluent-public/os/$confluent_profile/scripts/functions > /tmp/functions
. /tmp/functions
$python /etc/confluent/apiclient /confluent-public/os/$confluent_profile/kickstart.custom -o /tmp/kickstart.custom
run_remote pre.custom
run_remote_parts pre.d
if [ ! -e /tmp/installdisk ]; then
    run_remote_python getinstalldisk
fi
if [ -e /tmp/installdisk -a ! -e /tmp/partitioning ]; then
    echo clearpart --all --initlabel >> /tmp/partitioning
    echo ignoredisk --only-use $(cat /tmp/installdisk) >> /tmp/partitioning
    echo autopart --nohome $LUKSPARTY >> /tmp/partitioning
fi
if [ -e /usr/libexec/platform-python ]; then
    python=/usr/libexec/platform-python
elif [ -e /usr/bin/python3 ]; then
    python=/usr/byn/python3
else
    python=/usr/bin/python
fi
kill $logshowpid
