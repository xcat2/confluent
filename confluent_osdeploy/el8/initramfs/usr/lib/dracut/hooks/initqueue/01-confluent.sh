#!/bin/sh
[ -e /tmp/confluent.initq ] && return 0
echo -n "" > /tmp/confluent.initq
cd /sys/class/net
for currif in *; do
    ip link set $currif up
done
cd -
while ! grep MANAGER /tmp/confluent.info >& /dev/null; do
    /opt/confluent/bin/copernicus -t > /tmp/confluent.info
done
read ifidx <<EOF
$(grep ^MANAGER /tmp/confluent.info|grep fe80|sed -e s/.*%//)
EOF
read mgr << EOF
$(grep ^MANAGER /tmp/confluent.info|grep fe80|awk '{print $2}')
EOF
mgridx=${mgr#*%}
ifname=$(ip link |grep ^$ifidx:|awk '{print $2}')
ifname=${ifname%:}
echo $ifname > /tmp/net.ifaces
nodename=$(grep ^NODENAME /tmp/confluent.info|awk '{print $2}')
#TODO: blkid --label <whatever> to find mounted api

if [ -z "$apikey" ]; then
    apikey=$(/opt/confluent/bin/clortho $nodename $mgr)
fi
oum=$(umask)
umask 0077
echo $apikey > /etc/confluent.apikey
umask $oum
mgr="[$mgr]"
curl -f -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $apikey" https://$mgr/confluent-api/self/deploycfg > /tmp/confluent.deploycfg

dnsdomain=$(grep ^dnsdomain: /tmp/confluent.deploycfg)
dnsdomain=${dnsdomain#dnsdomain: }
hostname=$nodename
if [ ! -z "$dnsdomain" ] && [ "$dnsdomain" != "null" ]; then
    hostname=$hostname.$dnsdomain
fi
mgr=$(grep ^deploy_server: /tmp/confluent.deploycfg)
mgr=${mgr#deploy_server: }
profilename=$(grep ^profile: /tmp/confluent.deploycfg)
profilename=${profilename#profile: }
proto=$(grep ^protocol: /tmp/confluent.deploycfg)
proto=${proto#protocol: }
textconsole=$(grep ^textconsole: /tmp/confluent.deploycfg)
textconsole=${textconsole#textconsole: }
if [ $textconsole = "true" ] && ! grep console= /proc/cmdline > /dev/null; then
	autocons=$(cat /tmp/01-autocons.devnode)
	if [ ! -z "$autocons" ]; then
	    echo Auto-configuring installed system to use text console
	    echo Auto-configuring installed system to use text console > $autocons
	    cp /tmp/01-autocons.conf /etc/cmdline.d/
	else
	    echo "Unable to automatically detect requested text console"
	fi
fi

echo inst.repo=$proto://$mgr/confluent-public/os/$profilename/distribution >> /etc/cmdline.d/01-confluent.conf
echo inst.ks=$proto://$mgr/confluent-public/os/$profilename/kickstart >> /etc/cmdline.d/01-confluent.conf
kickstart=$proto://$mgr/confluent-public/os/$profilename/kickstart
root=anaconda-net:$proto://$mgr/confluent-public/os/$profilename/distribution
export kickstart
export root
autoconfigmethod=$(grep ipv4_method /tmp/confluent.deploycfg)
autoconfigmethod=${autoconfigmethod#ipv4_method: }
if [ "$autoconfigmethod" = "dhcp" ]; then
    echo ip=$ifname:dhcp >>  /etc/cmdline.d/01-confluent.conf
else
    v4addr=$(grep ^ipv4_address: /tmp/confluent.deploycfg)
    v4addr=${v4addr#ipv4_address: }
    v4gw=$(grep ^ipv4_gateway: /tmp/confluent.deploycfg)
    v4gw=${v4gw#ipv4_gateway: }
    if [ "$v4gw" = "null" ]; then
        v4gw=""
    fi
    v4nm=$(grep ipv4_netmask: /tmp/confluent.deploycfg)
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
done < /tmp/confluent.deploycfg

