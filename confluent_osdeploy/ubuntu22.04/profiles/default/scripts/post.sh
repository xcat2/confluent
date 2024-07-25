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
    $lukspass=$(cat /etc/confluent_lukspass)
    chroot /target apt install tpm2-initramfs-tool
    chroot /target tpm2-initramfs-tool seal --data "$(lukspass)" > /dev/null
    # The default PCR 7 mutates, and crypttab does not provide a way to pass args
    cat > /target/usr/bin/tpm2-initramfs-tool.pcr0 << EOF
#!/bin/sh
tpm2-initramfs-tool -p 0 \$*
EOF
    chmod 755 /target/usr/bin/tpm2-initramfs-tool.pcr0
    cat > /target/etc/initramfs-tools/hooks/tpm2-initramfs-tool <<EOF
. /usr/share/initramfs-tools/hook-functions

copy_exec /usr/lib/x86_64-linux-gnu/libtss2-tcti-device.so.0
copy_exec /usr/bin/tpm2-initramfs-tool
copy_exec /usr/bin/tpm2-initramfs-tool.pcr0
EOF
    chmod 755 /target/etc/initramfs-tools/hooks/tpm2-initramfs-tool
    chroot /target update-initramfs -u
fi
python3 /opt/confluent/bin/apiclient /confluent-api/self/updatestatus  -d 'status: staged'


umount /target/sys /target/dev /target/proc /target/run
) &
tail --pid $! -n 0 -F /target/var/log/confluent/confluent-post.log > /dev/console
