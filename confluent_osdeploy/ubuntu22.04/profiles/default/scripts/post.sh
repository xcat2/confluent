#!/bin/bash
cp -a /root/.ssh /target/root/
mkdir -p /target/etc/confluent/ssh/sshd_config.d/
chmod 700 /target/etc/confluent
cp /custom-installation/confluent/* /target/etc/confluent/
cp -a /custom-installation/tls /target/etc/confluent/
chmod go-rwx /etc/confluent/*
for i in /custom-installation/ssh/*.ca; do
    echo '@cert-authority *' $(cat $i) >> /target/etc/ssh/ssh_known_hosts
done
cp -a /etc/ssh/ssh_host* /target/etc/confluent/ssh/
cp -a /etc/ssh/sshd_config.d/confluent.conf /target/etc/confluent/ssh/sshd_config.d/
sshconf=/target/etc/ssh/ssh_config
if [ -d /target/etc/ssh/ssh_config.d/ ]; then
    sshconf=/target/etc/ssh/ssh_config.d/01-confluent.conf
fi
echo 'Host *' >> $sshconf
echo '    HostbasedAuthentication yes' >> $sshconf
echo '    EnableSSHKeysign yes' >> $sshconf
echo '    HostbasedKeyTypes *ed25519*' >> $sshconf
cp /etc/confluent/functions /target/etc/confluent/functions
source /etc/confluent/functions
mkdir -p /target/var/log/confluent
cp /var/log/confluent/* /target/var/log/confluent/
(
exec >> /target/var/log/confluent/confluent-post.log
exec 2>> /target/var/log/confluent/confluent-post.log
chmod 600 /target/var/log/confluent/confluent-post.log
curl -f https://$confluent_mgr/confluent-public/os/$confluent_profile/scripts/firstboot.sh > /target/etc/confluent/firstboot.sh
chmod +x /target/etc/confluent/firstboot.sh
cp /tmp/allnodes /target/root/.shosts
cp /tmp/allnodes /target/etc/ssh/shosts.equiv
if grep ^ntpservers: /target/etc/confluent/confluent.deploycfg > /dev/null; then
    ntps=$(sed -n '/^ntpservers:/,/^[^-]/p' /target/etc/confluent/confluent.deploycfg|sed 1d|sed '$d' | sed -e 's/^- //' | paste -sd ' ')
    sed -i "s/#NTP=/NTP=$ntps/" /target/etc/systemd/timesyncd.conf
fi
textcons=$(grep ^textconsole: /target/etc/confluent/confluent.deploycfg |awk '{print $2}')
updategrub=0
if [ "$textcons" = "true" ] && ! grep console= /proc/cmdline > /dev/null; then
    cons=""
    if [ -f /custom-installation/autocons.info ]; then
        cons=$(cat /custom-installation/autocons.info)
    fi
    if [ ! -z "$cons" ]; then
        sed -i 's/GRUB_CMDLINE_LINUX="\([^"]*\)"/GRUB_CMDLINE_LINUX="\1 console='${cons#/dev/}'"/' /target/etc/default/grub
        updategrub=1
    fi
fi
kargs=$(curl https://$confluent_mgr/confluent-public/os/$confluent_profile/profile.yaml | grep ^installedargs: | sed -e 's/#.*//')
if [ ! -z "$kargs" ]; then
    sed -i 's/GRUB_CMDLINE_LINUX="\([^"]*\)"/GRUB_CMDLINE_LINUX="\1 '"${kargs}"'"/' /target/etc/default/grub
fi
mkdir -p /opt/confluent/bin
mkdir -p /etc/confluent
cp -a /target/etc/confluent/* /etc/confluent
mkdir -p /target/opt/confluent/bin
cp /custom-installation/confluent/bin/apiclient /opt/confluent/bin/
cp /custom-installation/confluent/bin/apiclient /target/opt/confluent/bin

mount -o bind /dev /target/dev
mount -o bind /proc /target/proc
mount -o bind /sys /target/sys
mount -o bind /run /target/run
mount -o bind /sys/firmware/efi/efivars /target/sys/firmware/efi/efivars
if [ 1 = $updategrub ]; then
    chroot /target update-grub
fi

echo "Port 22" >> /etc/ssh/sshd_config
echo "Port 2222" >> /etc/ssh/sshd_config
echo "Match LocalPort 22" >> /etc/ssh/sshd_config
echo "    ChrootDirectory /target" >> /etc/ssh/sshd_config
kill -HUP $(cat /run/sshd.pid)
if [ -e /sys/firmware/efi ]; then
    bootnum=$(chroot /target efibootmgr | grep ubuntu | sed -e 's/ .*//' -e 's/\*//' -e s/Boot//)
    if [ ! -z "$bootnum" ]; then
        currboot=$(chroot /target efibootmgr | grep ^BootOrder: | awk '{print $2}')
        nextboot=$(echo $currboot| awk -F, '{print $1}')
        [ "$nextboot" = "$bootnum" ] || chroot /target efibootmgr -o $bootnum,$currboot
        chroot /target efibootmgr -D
    fi
fi
cat /target/etc/confluent/tls/*.pem > /target/etc/confluent/ca.pem
cat /target/etc/confluent/tls/*.pem > /target/usr/local/share/ca-certificates/confluent.crt
cat /target/etc/confluent/tls/*.pem > /etc/confluent/ca.pem
chroot /target update-ca-certificates
chroot /target bash -c "source /etc/confluent/functions; run_remote_python syncfileclient"
chroot /target bash -c "source /etc/confluent/functions; run_remote_python confignet"
chroot /target bash -c "source /etc/confluent/functions; run_remote_parts post.d"
source /target/etc/confluent/functions

run_remote_config post

if [ -f /etc/confluent_lukspass ]; then
    numdevs=$(lsblk -lo name,uuid|grep $(awk '{print $2}' < /target/etc/crypttab |sed -e s/UUID=//)|wc -l)
    if [ 0$numdevs -ne 1 ]; then
        wall "Unable to identify the LUKS device, halting install"
        while :; do sleep 86400; done
    fi
    CRYPTTAB_SOURCE=$(awk '{print $2}' /target/etc/crypttab)
    . /target/usr/lib/cryptsetup/functions
    crypttab_resolve_source

    if [ ! -e $CRYPTTAB_SOURCE ]; then
        wall "Unable to find $CRYPTTAB_SOURCE, halting install"
        while :; do sleep 86400; done
    fi
    $lukspass=$(cat /etc/confluent_lukspass)
    chroot /target apt install libtss2-rc0
    PASSWORD=$(lukspass) chroot /target  systemd-cryptenroll --tpm2-device=auto $CRYPTTAB_SOURCE
    cat >/target/etc/initramfs-tools/scripts/local-top/systemdecrypt << EOS
#!/bin/sh
case \$1 in
prereqs)
        echo
        exit 0
        ;;
esac

systemdecryptnow() {
. /usr/lib/cryptsetup/functions
local CRYPTTAB_SOURCE=\$(awk '{print \$2}' /systemdecrypt/crypttab)
local CRYPTTAB_NAME=\$(awk '{print \$1}' /systemdecrypt/crypttab)
crypttab_resolve_source
/lib/systemd/systemd-cryptsetup attach "\${CRYPTTAB_NAME}" "\${CRYPTTAB_SOURCE}" none tpm2-device=auto
}

systemdecryptnow
EOS
    chmod 755 /target/etc/initramfs-tools/scripts/local-top/systemdecrypt
    cat > /target/etc/initramfs-tools/hooks/systemdecrypt <<EOF
#!/bin/sh
case "\$1" in
    prereqs)
        echo
        exit 0
        ;;
esac

. /usr/share/initramfs-tools/hook-functions
mkdir -p \$DESTDIR/systemdecrypt
copy_exec /lib/systemd/systemd-cryptsetup /lib/systemd
for i in /lib/x86_64-linux-gnu/libtss2*
do
        copy_exec \${i} /lib/x86_64-linux-gnu
done
mkdir -p \$DESTDIR/scripts/local-top

echo /scripts/local-top/systemdecrypt >> \$DESTDIR/scripts/local-top/ORDER

if [ -f \$DESTDIR/cryptroot/crypttab ]; then
    mv \$DESTDIR/cryptroot/crypttab \$DESTDIR/systemdecrypt/crypttab
fi
EOF
    chroot /target update-initramfs -u
fi
python3 /opt/confluent/bin/apiclient /confluent-api/self/updatestatus  -d 'status: staged'


umount /target/sys /target/dev /target/proc /target/run
) &
tail --pid $! -n 0 -F /target/var/log/confluent/confluent-post.log > /dev/console
