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
function confluentpython() {
    if [ -x /usr/libexec/platform-python ]; then
        /usr/libexec/platform-python $*
    elif [ -x /usr/bin/python3 ]; then
        /usr/bin/python3 $*
    elif [ -x /usr/bin/python ]; then
        /usr/bin/python $*
    elif [ -x /usr/bin/python2 ]; then
        /usr/bin/python2 $*
    fi
}
exec >> /tmp/confluent-pre.log
exec 2>> /tmp/confluent-pre.log
chmod 600 /tmp/confluent-pre.log
tail -f /tmp/confluent-pre.log > /dev/tty &
logshowpid=$!
confluentpython /etc/confluent/apiclient >& /dev/null
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
MVER=$(grep VERSION_ID /etc/os-release|cut -d = -f 2 |cut -d . -f 1|cut -d '"' -f 2)
ntpsrvs=""
if [ "$MVER" -ge 9 ]; then
    if grep ^ntpservers: /etc/confluent/confluent.deploycfg > /dev/null; then
	for ntpsrv in $(sed -n '/^ntpservers:/,/^[^-]/p' /etc/confluent/confluent.deploycfg|sed 1d|sed '$d' | sed -e 's/^- //'); do
	    echo timesource --ntp-server $ntpsrv >> /tmp/timezone
        done
    fi
else
    if grep ^ntpservers: /etc/confluent/confluent.deploycfg > /dev/null; then
        ntpsrvs="--ntpservers="$(sed -n '/^ntpservers:/,/^[^-]/p' /etc/confluent/confluent.deploycfg|sed 1d|sed '$d' | sed -e 's/^- //' | paste -sd,)
    fi
fi
echo timezone $ntpsrvs $tz --utc >> /tmp/timezone
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
rm /etc/ssh/ssh_host_dsa_key*
for pubkey in /etc/ssh/ssh_host*key.pub; do
    certfile=${pubkey/.pub/-cert.pub}
    curl -sf -X POST -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $(cat /etc/confluent/confluent.apikey)" -d @$pubkey https://$confluent_mgr/confluent-api/self/sshcert > $certfile
    echo HostCertificate $certfile >> /etc/ssh/sshd_config.anaconda
done
/usr/sbin/sshd -f /etc/ssh/sshd_config.anaconda
cryptboot=$(grep ^encryptboot: /etc/confluent/confluent.deploycfg | awk '{print $2}')
LUKSPARTY=''
touch /tmp/cryptpkglist
touch /tmp/pkglist
touch /tmp/addonpackages
if [ "$cryptboot" == "tpm2" ]; then
	LUKSPARTY="--encrypted --passphrase=$(cat /etc/confluent/confluent.apikey)"
	echo $cryptboot >> /tmp/cryptboot
    echo clevis-dracut >> /tmp/cryptpkglist
fi


export confluent_mgr confluent_profile nodename
curl -sf https://$confluent_mgr/confluent-public/os/$confluent_profile/scripts/functions > /tmp/functions
. /tmp/functions
confluentpython /opt/confluent/bin/apiclient /confluent-public/os/$confluent_profile/kickstart.custom -o /tmp/kickstart.custom
run_remote pre.custom
run_remote_parts pre.d
confluentpython /etc/confluent/apiclient /confluent-public/os/$confluent_profile/kickstart -o /tmp/kickstart.base
if grep '^%include /tmp/pkglist' /tmp/kickstart.* > /dev/null; then
    confluentpython /etc/confluent/apiclient /confluent-public/os/$confluent_profile/packagelist -o /tmp/pkglist
fi
grep '^%include /tmp/partitioning' /tmp/kickstart.* > /dev/null || touch /tmp/installdisk
if [ ! -e /tmp/installdisk ]; then
    run_remote_python getinstalldisk
fi
confluentpython /etc/confluent/apiclient /confluent-public/os/$confluent_profile/partitioning -o /tmp/partitioning.template
grep '^%include /tmp/partitioning' /tmp/kickstart.* > /dev/null || rm /tmp/installdisk
if [ -e /tmp/installdisk -a ! -e /tmp/partitioning ]; then
    INSTALLDISK=$(cat /tmp/installdisk)
    sed -e s/%%INSTALLDISK%%/$INSTALLDISK/ -e s/%%LUKSHOOK%%/$LUKSPARTY/ /tmp/partitioning.template > /tmp/partitioning
    vgchange -a n >& /dev/null
    wipefs -a -f /dev/$INSTALLDISK >& /dev/null
fi
kill $logshowpid
