. /lib/dracut-lib.sh
confluent_whost=$confluent_mgr
if [[ "$confluent_whost" == *:* ]] && [[ "$confluent_whost" != "["* ]]; then
    confluent_whost="[$confluent_mgr]"
fi
mkdir -p /mnt/remoteimg /mnt/remote /mnt/overlay
TETHERED=0
if [ "untethered" = "$(getarg confluent_imagemethod)" ]; then
    mount -t tmpfs untethered /mnt/remoteimg
    curl https://$confluent_whost/confluent-public/os/$confluent_profile/rootimg.sfs -o /mnt/remoteimg/rootimg.sfs
else
    TETHERED=1
    confluent_urls="$confluent_urls https://$confluent_whost/confluent-public/os/$confluent_profile/rootimg.sfs"
    /opt/confluent/bin/urlmount $confluent_urls /mnt/remoteimg
fi
/opt/confluent/bin/confluent_imginfo /mnt/remoteimg/rootimg.sfs > /tmp/rootimg.info
loopdev=$(losetup -f)
export mountsrc=$loopdev
losetup -r $loopdev /mnt/remoteimg/rootimg.sfs
if grep '^Format: confluent_crypted' /tmp/rootimg.info > /dev/null; then
    while ! curl -sf -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $(cat /etc/confluent/confluent.apikey)" https://$confluent_whost/confluent-api/self/profileprivate/pending/rootimg.key > /tmp/rootimg.key; do
        echo "Unable to retrieve private key from $confluent_mgr (verify that confluent can access /var/lib/confluent/private/os/$confluent_profile/pending/rootimg.key)"
        sleep 1
    done
    cipher=$(head -n 1 /tmp/rootimg.key)
    key=$(tail -n 1 /tmp/rootimg.key)
    len=$(wc -c /mnt/remoteimg/rootimg.sfs | awk '{print $1}')
    len=$(((len-4096)/512))
    dmsetup create cryptimg --table "0 $len crypt $cipher $key 0 $loopdev 8"
    /opt/confluent/bin/confluent_imginfo /dev/mapper/cryptimg > /tmp/rootimg.info
    mountsrc=/dev/mapper/cryptimg
fi

if grep '^Format: squashfs' /tmp/rootimg.info > /dev/null; then
    mount -o ro $mountsrc /mnt/remote
elif grep  '^Format: confluent_multisquash' /tmp/rootimg.info; then
    tail -n +3 /tmp/rootimg.info  | awk '{gsub("/", "_"); print "echo 0 " $4 " linear '$mountsrc' " $3 " | dmsetup create mproot" $7}' > /tmp/setupmount.sh
    . /tmp/setupmount.sh
    cat /tmp/setupmount.sh |awk '{printf "mount /dev/mapper/"$NF" "; sub("mproot", ""); gsub("_", "/"); print "/mnt/remote"$NF}' > /tmp/mountparts.sh
    . /tmp/mountparts.sh
fi


#mount -t tmpfs overlay /mnt/overlay
modprobe zram
memtot=$(grep ^MemTotal: /proc/meminfo|awk '{print $2}')
memtot=$((memtot/2))$(grep ^MemTotal: /proc/meminfo | awk '{print $3'})
echo $memtot > /sys/block/zram0/disksize
mkfs.xfs /dev/zram0 > /dev/null
mount -o discard /dev/zram0 /mnt/overlay
if [ ! -f /tmp/mountparts.sh ]; then
    mkdir -p /mnt/overlay/upper /mnt/overlay/work
    mount -t overlay -o upperdir=/mnt/overlay/upper,workdir=/mnt/overlay/work,lowerdir=/mnt/remote disklessroot /sysroot
else
    for srcmount in $(cat /tmp/mountparts.sh | awk '{print $3}'); do
        mkdir -p /mnt/overlay${srcmount}/upper /mnt/overlay${srcmount}/work
        mount -t overlay -o upperdir=/mnt/overlay${srcmount}/upper,workdir=/mnt/overlay${srcmount}/work,lowerdir=${srcmount} disklesspart /sysroot${srcmount#/mnt/remote}
    done
fi
mkdir -p /sysroot/etc/ssh
mkdir -p /sysroot/etc/confluent
mkdir -p /sysroot/root/.ssh
cp /root/.ssh/* /sysroot/root/.ssh
chmod 700 /sysroot/root/.ssh
cp /etc/confluent/* /sysroot/etc/confluent/
cp /etc/ssh/*key* /sysroot/etc/ssh/
for pubkey in /etc/ssh/ssh_host*key.pub; do
    certfile=${pubkey/.pub/-cert.pub}
    privfile=${pubkey%.pub}
    if [ -s $certfile ]; then
        echo HostCertificate $certfile >> /sysroot/etc/ssh/sshd_config
    fi
    echo HostKey $privfile >> /sysroot/etc/ssh/sshd_config
done

mkdir -p /sysroot/dev /sysroot/sys /sysroot/proc /sysroot/run
if [ ! -z "$autocons" ]; then
    autocons=${autocons%,*}
    mkdir -p /run/systemd/generator/getty.target.wants
    ln -s /usr/lib/systemd/system/serial-getty@.service /run/systemd/generator/getty.target.wants/serial-getty@${autocons}.service
fi
while [ ! -e /sysroot/sbin/init ]; do
    echo "Failed to access root filesystem or it is missing /sbin/init"
    echo "System should be accessible through ssh at port 2222 with the appropriate key"
    while [ ! -e /sysroot/sbin/init ]; do
        sleep 1
    done
done
rootpassword=$(grep ^rootpassword: /etc/confluent/confluent.deploycfg)
rootpassword=${rootpassword#rootpassword: }
if [ "$rootpassword" = "null" ]; then
    rootpassword=""
fi

if [ ! -z "$rootpassword" ]; then
    sed -i "s@root:[^:]*:@root:$rootpassword:@" /sysroot/etc/shadow
fi
for i in /ssh/*.ca; do
    echo '@cert-authority *' $(cat $i) >> /sysroot/etc/ssh/ssh_known_hosts
done
echo HostbasedAuthentication yes >> /sysroot/etc/ssh/sshd_config
echo HostbasedUsesNameFromPacketOnly yes >> /sysroot/etc/ssh/sshd_config
echo IgnoreRhosts no >> /sysroot/etc/ssh/sshd_config
sshconf=/sysroot/etc/ssh/ssh_config
if [ -d /sysroot/etc/ssh/ssh_config.d/ ]; then
    sshconf=/sysroot/etc/ssh/ssh_config.d/01-confluent.conf
fi
echo 'Host *' >> $sshconf
echo '    HostbasedAuthentication yes' >> $sshconf
echo '    EnableSSHKeysign yes' >> $sshconf
echo '    HostbasedKeyTypes *ed25519*' >> $sshconf
curl -sf -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $(cat /etc/confluent/confluent.apikey)" https://$confluent_whost/confluent-api/self/nodelist > /sysroot/etc/ssh/shosts.equiv
cp /sysroot/etc/ssh/shosts.equiv /sysroot/root/.shosts
chmod 640 /sysroot/etc/ssh/*_key
chroot /sysroot chgrp ssh_keys /etc/ssh/*_key
cp /tls/*.pem /sysroot/etc/pki/ca-trust/source/anchors/
chroot /sysroot/ update-ca-trust
curl -sf https://$confluent_whost/confluent-public/os/$confluent_profile/scripts/onboot.service > /sysroot/etc/systemd/system/onboot.service
mkdir -p /sysroot/opt/confluent/bin
curl -sf https://$confluent_whost/confluent-public/os/$confluent_profile/scripts/onboot.sh > /sysroot/opt/confluent/bin/onboot.sh
chmod +x /sysroot/opt/confluent/bin/onboot.sh
cp /opt/confluent/bin/apiclient /sysroot/opt/confluent/bin
ln -s /etc/systemd/system/onboot.service /sysroot/etc/systemd/system/multi-user.target.wants/onboot.service
cp /etc/confluent/functions /sysroot/etc/confluent/functions
if grep installtodisk /proc/cmdline > /dev/null; then
    . /etc/confluent/functions
    run_remote installimage
    exec reboot -f
fi
mv /lib/modules/$(uname -r) /lib/modules/$(uname -r)-ramfs
ln -s /sysroot/lib/modules/$(uname -r) /lib/modules/
mv /lib/firmware /lib/firmware-ramfs
ln -s /sysroot/lib/firmware /lib/firmware
kill $(grep -l ^/usr/lib/systemd/systemd-udevd  /proc/*/cmdline|cut -d/ -f 3)
if [ $TETHERED -eq 1 ]; then
    (
        sleep 86400 &
        ONBOOTPID=$!
        mkdir -p /run/confluent
        echo $ONBOOTPID > /run/confluent/onboot_sleep.pid
        wait $ONBOOTPID
        losetup $loopdev --direct-io=on
        dd if=/mnt/remoteimg/rootimg.sfs iflag=nocache count=0 >& /dev/null
    ) &
    while [ ! -f /run/confluent/onboot_sleep.pid ]; do
        sleep 0.1
    done
fi
exec /opt/confluent/bin/start_root
