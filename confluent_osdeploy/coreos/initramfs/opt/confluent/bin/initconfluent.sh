#!/bin/bash
TRIES=0
oum=$(umask)
umask 0077
mkdir -p /etc/confluent
echo -n > /etc/confluent/confluent.info
umask $oum
cd /sys/class/net
while ! grep ^EXTMGRINFO: /etc/confluent/confluent.info | awk -F'|' '{print $3}' | grep 1 >& /dev/null && [ "$TRIES" -lt 60 ]; do
    TRIES=$((TRIES + 1))
    for currif in *; do
        ip link set $currif up
    done
    /opt/confluent/bin/copernicus -t > /etc/confluent/confluent.info
done
cd /
grep ^EXTMGRINFO: /etc/confluent/confluent.info || return 0  # Do absolutely nothing if no data at all yet
echo -n "" > /tmp/confluent.initq
# restart cmdline
echo -n "" > /etc/cmdline.d/01-confluent.conf
nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
cat /tls/*.pem > /etc/confluent/ca.pem
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
autoconfigmethod=$(grep ipv4_method /etc/confluent/confluent.deploycfg)
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
    if [[ "$ifname" == ib* ]]; then
        sed -i s/type=ethernet/type=infiniband/ /run/NetworkManager/system-connections/$ifname.nmconnection
        if ! grep '\[infiniband\]' /run/NetworkManager/system-connections/$ifname.nmconnection > /dev/null; then
            echo >> /run/NetworkManager/system-connections/$ifname.nmconnection
            echo '[infiniband]' >> /run/NetworkManager/system-connections/$ifname.nmconnection
            echo transport-mode=datagram >> /run/NetworkManager/system-connections/$ifname.nmconnection
        fi
    fi
fi
cat /proc/cmdline /etc/cmdline.d/01-confluent.conf | tr '\n' ' ' > /run/fakecmdline
mount -o bind /run/fakecmdline /proc/cmdline

curl -sf https://$confluent_mgr/confluent-public/os/$confluent_profile/rootfs.img | rdcore stream-hash /etc/coreos-live-want-rootfs | bsdtar -xf - -C /
