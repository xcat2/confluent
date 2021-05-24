root=1
rootok=1
netroot=confluent
clear
mkdir -p /etc/ssh
mkdir -p /var/tmp/
mkdir -p /var/empty/sshd
mkdir -p /etc/confluent
sed -i '/^root:x/d' /etc/passwd
echo root:x:0:0::/:/bin/bash >> /etc/passwd
echo sshd:x:30:30:SSH User:/var/empty/sshd:/sbin/nologin >> /etc/passwd

if ! grep console= /proc/cmdline >& /dev/null; then
    autocons=$(/opt/confluent/bin/autocons)
    autocons=${autocons##*/}
    echo "Automatic console configured for $autocons"
fi
echo "Initializng confluent diskless environment"
echo -n "udevd: "
/usr/lib/systemd/systemd-udevd --daemon
echo -n "Loading drivers..."
udevadm trigger
udevadm trigger --type=devices --action=add
udevadm settle
modprobe ib_ipoib
modprobe ib_umad
modprobe hfi1
modprobe mlx5_ib
echo "done"
cat > /etc/ssh/sshd_config << EOF
Port 2222
Subsystem       sftp    /usr/libexec/openssh/sftp-server
PermitRootLogin yes
AuthorizedKeysFile      .ssh/authorized_keys
EOF
mkdir /root/.ssh
mkdir /.ssh
cat /ssh/*pubkey > /root/.ssh/authorized_keys 2>/dev/null
cp /root/.ssh/authorized_keys /.ssh/
cat /tls/*.pem > /etc/confluent/ca.pem
mkdir -p /etc/pki/tls/certs
cat /tls/*.pem > /etc/pki/tls/certs/ca-bundle.crt
TRIES=0
touch /etc/confluent/confluent.info
cd /sys/class/net
echo -n "Scanning for network configuration..."
while ! grep ^EXTMGRINFO: /etc/confluent/confluent.info | awk -F'|' '{print $3}' | grep 1 >& /dev/null && [ "$TRIES" -lt 30 ]; do
    TRIES=$((TRIES + 1))
    for i in *; do
        ip link set $i up
    done
    /opt/confluent/bin/copernicus -t > /etc/confluent/confluent.info
done
cd /
nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
hostname $nodename
confluent_mgr=$(grep ^MANAGER: /etc/confluent/confluent.info|head -n 1 | awk '{print $2}')
if [[ $confluent_mgr == *%* ]]; then
    echo $confluent_mgr | awk -F% '{print $2}' > /tmp/confluent.ifidx
    ifidx=$(cat /tmp/confluent.ifidx)
    ifname=$(ip link |grep ^$ifidx:|awk '{print $2}')
    ifname=${ifname%:}
fi
needseal=1
oldumask=$(umask)
umask 0077
while [ -z "$confluent_apikey" ]; do
    /opt/confluent/bin/clortho $nodename $confluent_mgr > /etc/confluent/confluent.apikey
    if grep ^SEALED: /etc/confluent/confluent.apikey > /dev/null; then
	needseal=0
        sed -e s/^SEALED:// /etc/confluent/confluent.apikey | clevis-decrypt-tpm2 > /etc/confluent/confluent.apikey.decrypt
        mv /etc/confluent/confluent.apikey.decrypt /etc/confluent/confluent.apikey
    fi
    confluent_apikey=$(cat /etc/confluent/confluent.apikey)
    if [ -z "$confluent_apikey" ]; then
        echo "Unable to acquire node api key, no TPM2 sealed nor fresh token available, retrying..."
        sleep 10
    fi
done
if [[ $confluent_mgr == *:* ]]; then
    confluent_mgr="[$confluent_mgr]"
fi
if [ $needseal == 1 ]; then
    sealed=$(echo $confluent_apikey | clevis-encrypt-tpm2 {})
    if [ ! -z "$sealed" ]; then
        curl -sf -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $confluent_apikey" -d $sealed https://$confluent_mgr/confluent-api/self/saveapikey
    fi
fi
curl -sf -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $confluent_apikey" https://$confluent_mgr/confluent-api/self/deploycfg > /etc/confluent/confluent.deploycfg
umask $oldumask
autoconfigmethod=$(grep ipv4_method /etc/confluent/confluent.deploycfg |awk '{print $2}')
if [ "$autoconfigmethod" = "dhcp" ]; then
    echo -n "Attempting to use dhcp to bring up $ifname..."
    dhclient $ifname
    echo "Complete:"
    ip addr show dev $ifname
else
    v4addr=$(grep ^ipv4_address: /etc/confluent/confluent.deploycfg)
    v4addr=${v4addr#ipv4_address: }
    v4gw=$(grep ^ipv4_gateway: /etc/confluent/confluent.deploycfg)
    v4gw=${v4gw#ipv4_gateway: }
    if [ "$v4gw" = "null" ]; then
        v4gw=""
    fi
    v4nm=$(grep ^prefix: /etc/confluent/confluent.deploycfg)
    v4nm=${v4nm#prefix: }
    echo "Setting up $ifname as static at $v4addr/$v4nm"
    ip addr add dev $ifname $v4addr/$v4nm
    if [ ! -z "$v4gw" ]; then
        ip route add default via $v4gw
    fi
    mkdir -p /run/NetworkManager/system-connections
    cat > /run/NetworkManager/system-connections/$ifname.nmconnection << EOC
[connection]
id=eno1
EOC
    echo uuid=$(uuidgen) >> /run/NetworkManager/system-connections/$ifname.nmconnection
    cat >> /run/NetworkManager/system-connections/$ifname.nmconnection << EOC
type=ethernet
autoconnect-retries=1
EOC
    echo interface-name=$ifname >> /run/NetworkManager/system-connections/$ifname.nmconnection
    cat >> /run/NetworkManager/system-connections/$ifname.nmconnection << EOC
multi-connect=1
permissions=
wait-device-timeout=60000

[ethernet]
mac-address-blacklist=

[ipv4]
EOC
    echo address1=$v4addr/$v4nm >> /run/NetworkManager/system-connections/$ifname.nmconnection
    if [ ! -z "$v4gw" ]; then
        echo gateway=$v4gw >> /run/NetworkManager/system-connections/$ifname.nmconnection
    fi
    nameserversec=0
    nameservers=""
    while read -r entry; do
        if [ $nameserversec = 1 ]; then
            if [[ $entry == "-"* ]]; then
                nameservers="$nameservers"${entry#- }";"
                continue
            fi
        fi
        nameserversec=0
        if [ "${entry%:*}" = "nameservers" ]; then
            nameserversec=1
            continue
        fi
    done < /etc/confluent/confluent.deploycfg
    echo dns=$nameservers >> /run/NetworkManager/system-connections/$ifname.nmconnection
    dnsdomain=$(grep ^dnsdomain: /etc/confluent/confluent.deploycfg)
    dnsdomain=${dnsdomain#dnsdomain: }
    echo dns-search=$dnsdomain >> /run/NetworkManager/system-connections/$ifname.nmconnection
    cat >> /run/NetworkManager/system-connections/$ifname.nmconnection << EOC
may-fail=false
method=manual

[ipv6]
addr-gen-mode=eui64
method=auto

[proxy]
EOC
fi
chmod 600 /run/NetworkManager/system-connections/*.nmconnection
echo -n "Initializing ssh..."
ssh-keygen -A
for pubkey in /etc/ssh/ssh_host*key.pub; do
    certfile=${pubkey/.pub/-cert.pub}
    privfile=${pubkey%.pub}
    curl -sf -X POST -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $confluent_apikey" -d @$pubkey  https://$confluent_mgr/confluent-api/self/sshcert > $certfile
    if [ -s $certfile ]; then
        echo HostCertificate $certfile >> /etc/ssh/sshd_config
    fi
    echo HostKey $privfile >> /etc/ssh/sshd_config
done
/usr/sbin/sshd
confluent_profile=$(grep ^profile: /etc/confluent/confluent.deploycfg| awk '{print $2}')
confluent_proto=$(grep ^protocol: /etc/confluent/confluent.deploycfg| awk '{print $2}')
confluent_urls=""
for addr in $(grep ^MANAGER: /etc/confluent/confluent.info|awk '{print $2}'|sed -e s/%/%25/); do
    if [[ $addr == *:* ]]; then
        confluent_urls="$confluent_urls $confluent_proto://[$addr]/confluent-public/os/$confluent_profile/rootimg.sfs"
    else
        confluent_urls="$confluent_urls $confluent_proto://$addr/confluent-public/os/$confluent_profile/rootimg.sfs"
    fi
done
confluent_mgr=$(grep ^deploy_server: /etc/confluent/confluent.deploycfg| awk '{print $2}')
confluent_urls="$confluent_urls https://$confluent_mgr/confluent-public/os/$confluent_profile/rootimg.sfs"
mkdir -p /mnt/remoteimg /mnt/remote /mnt/overlay
/opt/confluent/bin/urlmount $confluent_urls /mnt/remoteimg
mount -o loop,ro /mnt/remoteimg/*.sfs /mnt/remote
mount -t tmpfs overlay /mnt/overlay
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
chmod 640 /sysroot/etc/ssh/*_key
chroot /sysroot chgrp ssh_keys /etc/ssh/*_key
chroot /sysroot cat /etc/confluent/ca.pem >> /etc/pki/tls/certs/ca-bundle.crt
curl -sf https://$confluent_mgr/confluent-public/os/$confluent_profile/scripts/onboot.service > /sysroot/etc/systemd/system/onboot.service
mkdir -p /sysroot/opt/confluent/bin
curl -sf https://$confluent_mgr/confluent-public/os/$confluent_profile/scripts/onboot.sh > /sysroot/opt/confluent/bin/onboot.sh
chmod +x /sysroot/opt/confluent/bin/onboot.sh
ln -s /etc/systemd/system/onboot.service /sysroot/etc/systemd/system/multi-user.target.wants/onboot.service
curl -sf https://$confluent_mgr/confluent-public/os/$confluent_profile/scripts/functions > /sysroot/etc/confluent/functions
exec /opt/confluent/bin/start_root

