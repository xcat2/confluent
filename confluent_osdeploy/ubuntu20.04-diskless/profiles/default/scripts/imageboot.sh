confluent_urls=""
confluent_proto=https
for addr in $(grep ^MANAGER: /etc/confluent/confluent.info|awk '{print $2}'|sed -e s/%/%25/); do
    if [[ $addr == *:* ]]; then
        confluent_urls="$confluent_urls $confluent_proto://[$addr]/confluent-public/os/$confluent_profile/rootimg.sfs"
    else
        confluent_urls="$confluent_urls $confluent_proto://$addr/confluent-public/os/$confluent_profile/rootimg.sfs"
    fi
done
mkdir -p /mnt/remoteimg /mnt/remote /mnt/overlay
TETHERED=1
if grep -q confluent_imagemethod=untethered /proc/cmdline || grep -q confluent_imagemethod=uncompressed /proc/cmdline; then
    TETHERED=0
    mount -t tmpfs untethered /mnt/remoteimg
    curl https://$confluent_mgr/confluent-public/os/$confluent_profile/rootimg.sfs -o /mnt/remoteimg/rootimg.sfs
else
    confluent_urls="$confluent_urls https://$confluent_mgr/confluent-public/os/$confluent_profile/rootimg.sfs"
    /opt/confluent/bin/urlmount $confluent_urls /mnt/remoteimg
fi
/opt/confluent/bin/confluent_imginfo /mnt/remoteimg/rootimg.sfs > /tmp/rootimg.info
loopdev=$(losetup -f)
export mountsrc=$loopdev
losetup -r $loopdev /mnt/remoteimg/rootimg.sfs
if grep '^Format: confluent_crypted' /tmp/rootimg.info > /dev/null; then
    while ! curl -sf -H "CONFLUENT_NODENAME: $confluent_nodename" -H "CONFLUENT_APIKEY: $(cat /etc/confluent/confluent.apikey)" https://$confluent_mgr/confluent-api/self/profileprivate/pending/rootimg.key > /tmp/rootimg.key; do
        echo "Unable to retrieve private key from $confluent_mgr (verify that confluent can access /var/lib/confluent/private/os/$confluent_profile/pending/rootimg.key)"
        sleep 1
    done
    cipher=$(head -n 1 /tmp/rootimg.key)
    key=$(tail -n 1 /tmp/rootimg.key)
    len=$(ls -l /mnt/remoteimg/rootimg.sfs | awk '{print $3}')
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
mkdir /sysroot
if ! grep -q confluent_imagemethod=uncompressed /proc/cmdline; then
    modprobe zram
    memtot=$(grep ^MemTotal: /proc/meminfo|awk '{print $2}')
    memtot=$((memtot/2))$(grep ^MemTotal: /proc/meminfo | awk '{print $3'})
    echo $memtot > /sys/block/zram0/disksize
    modprobe xfs
    mkfs.xfs /dev/zram0 > /dev/null
    if [ "$TETHERED" = 1 ]; then
         mount -o discard /dev/zram0 /mnt/overlay
    else
         mount -o discard /dev/zram0 /sysroot
    fi
elif grep -q confluent_imagemethod=uncompressed /proc/cmdline; then
    mount -t tmpfs disklessroot /sysroot
fi
if [ "$TETHERED" = 0 ]; then
    echo -en "Decrypting and extracting root filesystem: 0%\r"
        srcsz=$(du -sk /mnt/remote | awk '{print $1}')
        while [ -f /mnt/remoteimg/rootimg.sfs ]; do
        dstsz=$(du -sk /sysroot | awk '{print $1}')
        pct=$((dstsz * 100 / srcsz))
        if [ $pct -gt 99 ]; then
            pct=99
        fi
        echo -en "Decrypting and extracting root filesystem: $pct%\r"
        sleep 0.25
    done &
    cp -a /mnt/remote/* /sysroot/
    umount /mnt/remote
    if [ -e /dev/mapper/cryptimg ]; then
        dmsetup remove cryptimg
    fi
    losetup -d $loopdev
    rm /mnt/remoteimg/rootimg.sfs
    umount /mnt/remoteimg
    wait
    echo -e "Decrypting and extracting root filesystem: 100%"
elif [ ! -f /tmp/mountparts.sh ]; then
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
cp /tls/* /sysroot/etc/ssl/certs
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
while [ ! -e /sysroot/sbin/init ] && [ ! -h /sysroot/sbin/init ]; do
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
curl -sf -H "CONFLUENT_NODENAME: $confluent_nodename" -H "CONFLUENT_APIKEY: $(cat /etc/confluent/confluent.apikey)" https://$confluent_mgr/confluent-api/self/nodelist > /sysroot/etc/ssh/shosts.equiv
cp /sysroot/etc/ssh/shosts.equiv /sysroot/root/.shosts
echo $confluent_nodename > /sysroot/etc/hostname
chmod 600 /sysroot/etc/ssh/*_key
mkdir -p /sysroot/usr/share/ca-certificates/confluent/
cp /tls/*.pem /sysroot/usr/share/ca-certificates/confluent/
chroot /sysroot/ update-ca-certificates
curl -sf https://$confluent_mgr/confluent-public/os/$confluent_profile/scripts/onboot.service > /sysroot/etc/systemd/system/onboot.service
mkdir -p /sysroot/opt/confluent/bin
curl -sf https://$confluent_mgr/confluent-public/os/$confluent_profile/scripts/onboot.sh > /sysroot/opt/confluent/bin/onboot.sh
chmod +x /sysroot/opt/confluent/bin/onboot.sh
cp /opt/confluent/bin/apiclient /sysroot/opt/confluent/bin
ln -s /etc/systemd/system/onboot.service /sysroot/etc/systemd/system/multi-user.target.wants/onboot.service
cp /etc/confluent/functions /sysroot/etc/confluent/functions
mv /lib/modules/$(uname -r) /lib/modules/$(uname -r)-ramfs
ln -s /sysroot/lib/modules/$(uname -r) /lib/modules/
mv /lib/firmware /lib/firmware-ramfs
ln -s /sysroot/lib/firmware /lib/firmware
rm /sysroot/etc/machine-id
if [ -e /sys/devices/virtual/dmi/id/product_uuid ]; then
    (hostname; cat /sys/devices/virtual/dmi/id/product_uuid) | sha512sum | head -c 32 > /sysroot/etc/machine-id
else
    hostname | sha512sum | head -c 32 > /sysroot/etc/machine-id
fi
echo >> /sysroot/etc/machine-id
ipv4=$(grep ^ipv4_address: /etc/confluent/confluent.deploycfg | awk '{print $2}')
ipv4method=$(grep ^ipv4_method: /etc/confluent/confluent.deploycfg | awk '{print $2}')
ipv4gateway=$(grep ^ipv4_gateway: /etc/confluent/confluent.deploycfg | awk '{print $2}')
if [ -n "$ipv4" -a "$ipv4" != "none" -a "$ipv4" != "null" ]; then
    iface=$(ip a|grep ${ipv4}/|awk '{print $NF}')
    ipwithcidr=$(ip a | grep ${ipv4}/ | awk '{print $2}')
    cat > /sysroot/etc/netplan/10-${iface}-confluentcfg.yaml <<EOF
network:
  ethernets:
    $iface:
EOF
    if [ "$ipv4method" = "dhcp" ]; then
        echo "      dhcp4: yes" >> /sysroot/etc/netplan/10-${iface}-confluentcfg.yaml
    else
        echo "      dhcp4: no" >> /sysroot/etc/netplan/10-${iface}-confluentcfg.yaml
        echo "      addresses: [$ipwithcidr]" >> /sysroot/etc/netplan/10-${iface}-confluentcfg.yaml

        nameservers=$(sed -n '/^nameservers:/,/^[^-]/p' /etc/confluent/confluent.deploycfg | grep ^- | cut -d ' ' -f 2 | sed -e 's/ //')
        if [ -n "$nameservers" ]; then
            echo "      nameservers:" >> /sysroot/etc/netplan/10-${iface}-confluentcfg.yaml
            echo "        addresses:" >> /sysroot/etc/netplan/10-${iface}-confluentcfg.yaml
            for nameserver in $nameservers; do
                echo "          - $nameserver" >> /sysroot/etc/netplan/10-${iface}-confluentcfg.yaml
            done
        fi
        if [ -n "$ipv4gateway" -a "$ipv4gateway" != "none" -a "$ipv4gateway" != "null" ]; then
            cat >> /sysroot/etc/netplan/10-${iface}-confluentcfg.yaml <<EOF
        routes:
          - to: default
            via: $ipv4gateway
EOF
        fi
    fi
    echo "  version: 2" >> /sysroot/etc/netplan/10-${iface}-confluentcfg.yaml
fi
if grep installtodisk /proc/cmdline > /dev/null; then
    . /etc/confluent/functions
    run_remote installimage
    exec reboot -f
fi
exec /opt/confluent/bin/start_root
