#!/bin/sh
[ -e /tmp/confluent.initq ] && return 0
if [ -f /tmp/dd_disk ]; then
    for dd in $(cat /tmp/dd_disk); do
        if [ -e $dd ]; then
            driver-updates --disk $dd $dd
        fi
    done
fi
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
mkdir -p /var/log/xcat

#TODO: blkid --label <whatever> to find mounted api
nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
mgr=$(grep ^EXTMGRINFO: /etc/confluent/confluent.info| sed -e 's/^EXTMGRINFO: //' | awk -F'|' '{print $1 " " $2 " " $3}' |grep 1$ | awk 'NR < 2')
if [ -z "$mgr" ]; then
    mgr=$(grep ^EXTMGRINFO: /etc/confluent/confluent.info| sed -e 's/^EXTMGRINFO: //' | awk -F'|' '{print $1 " " $2 " " $3}' | awk 'NR < 2')
fi
mgtiface=$(echo $mgr | awk '{print $2}')
mgr=$(echo $mgr | awk '{print $1}')
if [ ! -f /etc/confluent/confluent.apikey ]; then
    /opt/confluent/bin/clortho $nodename $mgr > /etc/confluent/confluent.apikey
fi
if echo $mgr | grep '%' > /dev/null; then
    echo $mgr | awk -F% '{print $2}' > /tmp/confluent.ifidx
fi
apikey=$(cat /etc/confluent/confluent.apikey)
if echo $mgr | grep ':' > /dev/null; then
    mgr="[$mgr]"
fi
curl -f -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $apikey" -H "CONFLUENT_MGTIFACE: $mgtiface" https://$mgr/confluent-api/self/deploycfg > /etc/confluent/confluent.deploycfg




cat /tls/*.pem > /etc/confluent/ca.pem
ifidx=$(cat /tmp/confluent.ifidx)
ifname=$(ip link |grep ^$ifidx:|awk '{print $2}')
ifname=${ifname%:}
echo $ifname > /tmp/net.ifaces

dnsdomain=$(grep ^dnsdomain: /etc/confluent/confluent.deploycfg)
dnsdomain=${dnsdomain#dnsdomain: }
hostname=$nodename
if [ ! -z "$dnsdomain" ] && [ "$dnsdomain" != "null" ]; then
    hostname=$hostname.$dnsdomain
fi
mgr=$(grep ^deploy_server: /etc/confluent/confluent.deploycfg)
mgr=${mgr#deploy_server: }
if ! grep XCAT /proc/cmdline > /dev/null; then
        echo XCAT=$mgr:3001 >> /etc/cmdline.d/01-confluent.conf
fi
profilename=$(grep ^profile: /etc/confluent/confluent.deploycfg)
profilename=${profilename#profile: }
proto=$(grep ^protocol: /etc/confluent/confluent.deploycfg)
proto=${proto#protocol: }
textconsole=$(grep ^textconsole: /etc/confluent/confluent.deploycfg)
textconsole=${textconsole#textconsole: }
if [ "$textconsole" = "true" ] && ! grep console= /proc/cmdline > /dev/null; then
        autocons=$(cat /tmp/01-autocons.devnode)
        if [ ! -z "$autocons" ]; then
            echo Auto-configuring installed system to use text console
            echo Auto-configuring installed system to use text console > $autocons
            cp /tmp/01-autocons.conf /etc/cmdline.d/
        else
            echo "Unable to automatically detect requested text console"
        fi
fi

echo imgurl=$proto://$mgr/confluent-public/os/$profilename/rootimg.cpio.gz >> /etc/cmdline.d/01-confluent.conf
autoconfigmethod=$(grep ipv4_method /etc/confluent/confluent.deploycfg)
autoconfigmethod=${autoconfigmethod#ipv4_method: }
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
    mkdir -p /etc/sysconfig/network-scripts
    ifcfg=/etc/sysconfig/network-scripts/ifcfg-$ifname
    echo DEVICE=$ifname >> $ifcfg
    echo NAME=$ifname >> $ifcfg
    echo IPADDR=$v4addr >> $ifcfg
    echo GATEWAY=$v4gw >> $ifcfg
    echo NETMASK=$v4nm >> $ifcfg
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

