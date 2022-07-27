#!/bin/bash
TRIES=0
oum=$(umask)
umask 0077
mkdir -p /etc/confluent
echo -n > /etc/confluent/confluent.info
umask $oum
if [ -e /dev/disk/by-label/CNFLNT_IDNT ]; then
    tmnt=$(mktemp -d)
    tcfg=$(mktemp)
    mount /dev/disk/by-label/CNFLNT_IDNT $tmnt
    cd $tmnt
    deploysrvs=$(sed -n '/^deploy_servers:/, /^[^-]/p' cnflnt.yml |grep ^-|sed -e 's/^- //'|grep -v :)
    nodename=$(grep ^nodename: cnflnt.yml|awk '{print $2}')
    sed -n '/^net_cfgs:/, /^[^- ]/{/^[^- ]/!p}' cnflnt.yml |sed -n '/^-/, /^-/{/^-/!p}'| sed -e 's/^[- ]*//'> $tcfg
    autoconfigmethod=$(grep ^ipv4_method: $tcfg)
    autoconfigmethod=${autoconfigmethod#ipv4_method: }
    if [ "$autoconfigmethod" = "dhcp" ]; then
        /usr/libexec/nm-initrd-generator ip=:dhcp
    else
        v4addr=$(grep ^ipv4_address: $tcfg)
        v4addr=${v4addr#ipv4_address: }
        v4addr=${v4addr%/*}
        v4gw=$(grep ^ipv4_gateway: $tcfg)
        v4gw=${v4gw#ipv4_gateway: }
        if [ "$v4gw" = "null" ]; then
            v4gw=""
        fi
        v4nm=$(grep ipv4_netmask: $tcfg)
        v4nm=${v4nm#ipv4_netmask: }
        /usr/libexec/nm-initrd-generator ip=$v4addr::$v4gw:$v4nm:$hostname::none
    fi
    NetworkManager --configure-and-quit=initrd --no-daemon
    hmackeyfile=$(mktemp)
    echo -n $(grep ^apitoken: cnflnt.yml|awk '{print $2}') > $hmackeyfile
    cd -
    umount $tmnt
    passfile=$(mktemp)
    passcrypt=$(mktemp)
    hmacfile=$(mktemp)
    ln -s /opt/confluent/bin/clortho /opt/confluent/bin/genpasshmac
    /opt/confluent/bin/genpasshmac $passfile $passcrypt $hmacfile $hmackeyfile
    for deployer in $deploysrvs; do
        if curl -f -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_CRYPTHMAC: $(cat $hmacfile)" -d@$passcrypt -k https://$deployer/confluent-api/self/registerapikey; then
            cp $passfile /etc/confluent/confluent.apikey
            confluent_apikey=$(cat /etc/confluent/confluent.apikey)
            curl -sf -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $confluent_apikey" https://$deployer/confluent-api/self/deploycfg > /etc/confluent/confluent.deploycfg
            curl -sf -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $confluent_apikey" https://$deployer/confluent-api/self/profileprivate/pending/config.ign > /config.ign
            [ -s /config.ign ] || rm /config.ign
            confluent_profile=$(grep ^profile: /etc/confluent/confluent.deploycfg)
            confluent_profile=${confluent_profile#profile: }
            curl -sf https://$deployer/confluent-public/os/$confluent_profile/rootfs.img | rdcore stream-hash /etc/coreos-live-want-rootfs | bsdtar -xf - -C /
            exit 0
        fi
    done
fi
cd /sys/class/net
echo "Searching for confluent deployment server...." > /dev/console
while ! grep ^NODE /etc/confluent/confluent.info; do
    while ! grep ^EXTMGRINFO: /etc/confluent/confluent.info | awk -F'|' '{print $3}' | grep 1 >& /dev/null && [ "$TRIES" -lt 60 ]; do
        TRIES=$((TRIES + 1))
        for currif in *; do
            ip link set $currif up
        done
        /opt/confluent/bin/copernicus -t > /etc/confluent/confluent.info
    done
    if ! grep ^NODE /etc/confluent/confluent.info; then
        echo 'Current net config:' > /dev/console
        ip -br a > /dev/console
        exit 1
    fi
done
echo "Found confluent deployment services on local network" > /dev/console
cd /
echo -n "" > /tmp/confluent.initq
# restart cmdline
echo -n "" > /etc/cmdline.d/01-confluent.conf
nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
cat /tls/*.pem > /etc/confluent/ca.pem
confluent_mgr=$(grep ^MANAGER: /etc/confluent/confluent.info|head -n 1 | awk '{print $2}')
echo "Connecting to confluent server: $confluent_mgr" > /dev/console
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
        echo "Unable to acquire node api key, no TPM2 sealed nor fresh token available, retrying..." > /dev/console
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
curl -sf -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $confluent_apikey" https://$confluent_mgr/confluent-api/self/profileprivate/pending/config.ign > /config.ign
[ -s /config.ign ] || rm /config.ign

umask $oldumask
autoconfigmethod=$(grep ^ipv4_method: /etc/confluent/confluent.deploycfg)
autoconfigmethod=${autoconfigmethod#ipv4_method: }
confluent_profile=$(grep ^profile: /etc/confluent/confluent.deploycfg)
confluent_profile=${confluent_profile#profile: }

if [ "$autoconfigmethod" = "dhcp" ]; then
    echo ip=$ifname:dhcp >>  /etc/cmdline.d/01-confluent.conf
else
    v4addr=$(grep ^ipv4_address: /etc/confluent/confluent.deploycfg)
    v4addr=${v4addr#ipv4_address: }
    v4gw=$(grep ^ipv4_gateway: /etc/confluent/confluent.deploycfg)
    v4gw=${v4gw#ipv4_gateway: }
    if [ "$v4gw" = "null" ]; then
        v4gw=""
    fi
    v4nm=$(grep ipv4_netmask: /etc/confluent/confluent.deploycfg)
    v4nm=${v4nm#ipv4_netmask: }
    echo ip=$v4addr::$v4gw:$v4nm:$hostname:$ifname:none >> /etc/cmdline.d/01-confluent.conf
fi
nameserversec=0
while read -r entry; do
    if [ $nameserversec = 1 ]; then
        if [[ $entry == "-"* ]] && [[ $entry != "- ''" ]]; then
            echo nameserver=${entry#- } >> /etc/cmdline.d/01-confluent.conf
            continue
        fi
    fi
    nameserversec=0
    if [ "${entry%:*}" = "nameservers" ]; then
        nameserversec=1
        continue
    fi
done < /etc/confluent/confluent.deploycfg

if [ -e /lib/nm-lib.sh ]; then
    . /lib/nm-lib.sh
    nm_generate_connections
    sed -i 's/method=disabled/method=link-local/' /run/NetworkManager/system-connections/*.nmconnection
   if [ -f /run/NetworkManager/system-connections/$ifname.nmconnection ]; then
        rm /run/NetworkManager/system-connections/default_connection.nmconnection
    fi
    if [[ "$ifname" == ib* ]]; then
        sed -i s/type=ethernet/type=infiniband/ /run/NetworkManager/system-connections/$ifname.nmconnection
        if ! grep '\[infiniband\]' /run/NetworkManager/system-connections/$ifname.nmconnection > /dev/null; then
            echo >> /run/NetworkManager/system-connections/$ifname.nmconnection
            echo '[infiniband]' >> /run/NetworkManager/system-connections/$ifname.nmconnection
            echo transport-mode=datagram >> /run/NetworkManager/system-connections/$ifname.nmconnection
        fi
    fi
fi
#cat /proc/cmdline /etc/cmdline.d/01-confluent.conf | tr '\n' ' ' > /run/fakecmdline
#chcon system_u:object_r:proc_t:s0 /run/fakecmdline
#mount -o bind /run/fakecmdline /proc/cmdline

curl -sf https://$confluent_mgr/confluent-public/os/$confluent_profile/rootfs.img | rdcore stream-hash /etc/coreos-live-want-rootfs | bsdtar -xf - -C /
