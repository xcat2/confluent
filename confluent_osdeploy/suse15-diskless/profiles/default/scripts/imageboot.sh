. /lib/dracut-lib.sh
mkdir -p /mnt/remoteimg /mnt/remote /mnt/overlay
if [ "untethered" = "$(getarg confluent_imagemethod)" ]; then
    mount -t tmpfs untethered /mnt/remoteimg
    curl https://$confluent_mgr/confluent-public/os/$confluent_profile/rootimg.sfs -o /mnt/remoteimg/rootimg.sfs
else
    confluent_urls="$confluent_urls https://$confluent_mgr/confluent-public/os/$confluent_profile/rootimg.sfs"
    /opt/confluent/bin/urlmount $confluent_urls /mnt/remoteimg
fi
mount -o loop,ro /mnt/remoteimg/*.sfs /mnt/remote
#mount -t tmpfs overlay /mnt/overlay
modprobe zram
memtot=$(grep ^MemTotal: /proc/meminfo|awk '{print $2}')
memtot=$((memtot/2))$(grep ^MemTotal: /proc/meminfo | awk '{print $3'})
echo $memtot > /sys/block/zram0/disksize
mkfs.xfs /dev/zram0 > /dev/null
mount -o discard /dev/zram0 /mnt/overlay
mkdir -p /mnt/overlay/upper /mnt/overlay/work
mount -t overlay -o upperdir=/mnt/overlay/upper,workdir=/mnt/overlay/work,lowerdir=/mnt/remote disklessroot /sysroot
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
curl -sf -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $(cat /etc/confluent/confluent.apikey)" https://$confluent_mgr/confluent-api/self/nodelist > /sysroot/etc/ssh/shosts.equiv
cp /sysroot/etc/ssh/shosts.equiv /sysroot/root/.shosts
chmod 600 /sysroot/etc/ssh/*_key
chroot /sysroot cat /etc/confluent/ca.pem >> /sysroot/var/lib/ca-certificates/ca-bundle.pem
curl -sf https://$confluent_mgr/confluent-public/os/$confluent_profile/scripts/onboot.service > /sysroot/etc/systemd/system/onboot.service
mkdir -p /sysroot/opt/confluent/bin
curl -sf https://$confluent_mgr/confluent-public/os/$confluent_profile/scripts/onboot.sh > /sysroot/opt/confluent/bin/onboot.sh
chmod +x /sysroot/opt/confluent/bin/onboot.sh
ln -s /etc/systemd/system/onboot.service /sysroot/etc/systemd/system/multi-user.target.wants/onboot.service
cp /etc/confluent/functions /sysroot/etc/confluent/functions

nameserversec=0
nameservers=""
while read -r entry; do
    if [ $nameserversec = 1 ]; then
        if [[ $entry == "-"* ]]; then
            nameservers="$nameservers"${entry#- }" "
            continue
        fi
    fi
    nameserversec=0
    if [ "${entry%:*}" = "nameservers" ]; then
        nameserversec=1
        continue
    fi
done < /etc/confluent/confluent.deploycfg
nameservers=${nameservers% }
sed -i 's/^NETCONFIG_DNS_STATIC_SERVERS="/NETCONFIG_DNS_STATIC_SERVERS="'"$nameservers"/ /sysroot/etc/sysconfig/network/config
dnsdomain=$(grep ^dnsdomain: /etc/confluent/confluent.deploycfg)
dnsdomain=${dnsdomain#dnsdomain: }
sed -i 's/^NETCONFIG_DNS_STATIC_SEARCHLIST="/NETCONFIG_DNS_STATIC_SEARCHLIST="'$dnsdomain/ /sysroot/etc/sysconfig/network/config
cp /run/confluent/ifroute-* /run/confluent/ifcfg-* /sysroot/etc/sysconfig/network
exec /opt/confluent/bin/start_root
