#!/bin/sh
[ -e /tmp/confluent.initq ] && return 0
udevadm trigger
udevadm trigger --type=devices --action=add
udevadm settle
modprobe ib_ipoib
modprobe ib_umad
modprobe hfi1
modprobe mlx5_ib
function confluentpython() {
    if [ -x /usr/libexec/platform-python ]; then
        /usr/libexec/platform-python $*
    elif [ -x /usr/bin/python3 ]; then
        /usr/bin/python3 $*
    elif [ -x /usr/bin/python ]; then
        /usr/bin/python $*
    elif [ -x /usr/bin/python2 ]; then
        /usr/bin/python2 $*
    fi
}
if [ -f /tmp/dd_disk ]; then
    for dd in $(cat /tmp/dd_disk); do
        if [ -e $dd ]; then
            driver-updates --disk $dd $dd
        fi
    done
fi
vlaninfo=$(getarg vlan)
if [ ! -z "$vlaninfo" ]; then
        vldev=${vlaninfo#*:}
        vlid=${vlaninfo#*.}
        vlid=${vlid%:*}
        ip link add link $vldev name $vldev.$vlid type vlan id $vlid
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

nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
#TODO: blkid --label <whatever> to find mounted api

cat /tls/*.pem > /etc/confluent/ca.pem
confluentpython /opt/confluent/bin/apiclient /confluent-api/self/deploycfg2 > /etc/confluent/confluent.deploycfg
ifidx=$(cat /tmp/confluent.ifidx)
ifname=$(ip link |grep ^$ifidx:|awk '{print $2}')
ifname=${ifname%:}
ifname=${ifname%@*}
echo $ifname > /tmp/net.ifaces

dnsdomain=$(grep ^dnsdomain: /etc/confluent/confluent.deploycfg)
dnsdomain=${dnsdomain#dnsdomain: }
hostname=$nodename
if [ ! -z "$dnsdomain" ] && [ "$dnsdomain" != "null" ]; then
    hostname=$hostname.$dnsdomain
fi
v6cfg=$(grep ^ipv6_method: /etc/confluent/confluent.deploycfg)
v6cfg=${v6cfg#ipv6_method: }
if [ "$v6cfg" = "static" ]; then
    mgr=$(grep ^deploy_server_v6: /etc/confluent/confluent.deploycfg)
    mgr=${mgr#deploy_server_v6: }
    mgr="[$mgr]"
else
    mgr=$(grep ^deploy_server: /etc/confluent/confluent.deploycfg)
    mgr=${mgr#deploy_server: }
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

echo inst.repo=$proto://$mgr/confluent-public/os/$profilename/distribution >> /etc/cmdline.d/01-confluent.conf
echo inst.ks=$proto://$mgr/confluent-public/os/$profilename/kickstart >> /etc/cmdline.d/01-confluent.conf
kickstart=$proto://$mgr/confluent-public/os/$profilename/kickstart
root=anaconda-net:$proto://$mgr/confluent-public/os/$profilename/distribution
export kickstart
export root
autoconfigmethod=$(grep ipv4_method /etc/confluent/confluent.deploycfg)
autoconfigmethod=${autoconfigmethod#ipv4_method: }
if [ "$v6cfg" = "static" ]; then
    v6addr=$(grep ^ipv6_address: /etc/confluent/confluent.deploycfg)
    v6addr=${v6addr#ipv6_address: }
    v6addr="[$v6addr]"
    v6gw=$(grep ^ipv6_gateway: /etc/confluent/confluent.deploycfg)
    v6gw=${v6gw#ipv6_gateway: }
    if [ "$v6gw" = "null" ]; then
        v6gw=""
    else
        v6gw="[$v6gw]"
    fi
    v6nm=$(grep ipv6_prefix: /etc/confluent/confluent.deploycfg)
    v6nm=${v6nm#ipv6_prefix: }
    echo ip=$v6addr::$v6gw:$v6nm:$hostname:$ifname:none >> /etc/cmdline.d/01-confluent.conf
elif [ "$autoconfigmethod" = "dhcp" ]; then
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

