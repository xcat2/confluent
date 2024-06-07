#!/bin/sh
[ -e /tmp/confluent.initq ] && return 0
. /lib/dracut-lib.sh
setsid sh -c 'exec bash <> /dev/tty2 >&0 2>&1' &
if [ -f /tmp/dd_disk ]; then
    for dd in $(cat /tmp/dd_disk); do
        if [ -e $dd ]; then
            driver-updates --disk $dd $dd
	    rm $dd
        fi
    done
    rm /tmp/dd_disk
fi
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
TRIES=5
while [ ! -e /dev/disk/by-label ] && [ $TRIES -gt 0 ]; do
    sleep 2
    TRIES=$((TRIES - 1))
done
if [ -e /dev/disk/by-label/CNFLNT_IDNT ]; then
    tmnt=/tmp/idntmnt
    mkdir -p $tmnt
    tcfg=/tmp/idnttmp
    mount /dev/disk/by-label/CNFLNT_IDNT $tmnt
    cd $tmnt
    deploysrvs=$(sed -n '/^deploy_servers:/, /^[^-]/p' cnflnt.yml |grep ^-|sed -e 's/^- //'|grep -v :)
    nodename=$(grep ^nodename: cnflnt.yml|awk '{print $2}')
    sed -n '/^net_cfgs:/, /^[^- ]/{/^[^- ]/!p}' cnflnt.yml |sed -n '/^-/, /^-/{/^-/!p}'| sed -e 's/^[- ]*//'> $tcfg
    autoconfigmethod=$(grep ^ipv4_method: $tcfg)
    autoconfigmethod=${autoconfigmethod#ipv4_method: }
     for i in /sys/class/net/*; do
        ip link set $(basename $i) down
        udevadm info $i | grep ID_NET_DRIVER=cdc_ether > /dev/null &&  continue
        ip link set $(basename $i) up
    done
    for NICGUESS in $(ip link|grep LOWER_UP|grep -v LOOPBACK| awk '{print $2}' | sed -e 's/:$//'); do
        if [ "$autoconfigmethod" = "dhcp" ]; then
            /usr/libexec/nm-initrd-generator ip=$NICGUESS:dhcp
        else
            v4addr=$(grep ^ipv4_address: $tcfg)
            v4addr=${v4addr#ipv4_address: }
            v4plen=${v4addr#*/}
            v4addr=${v4addr%/*}
            v4gw=$(grep ^ipv4_gateway: $tcfg)
            v4gw=${v4gw#ipv4_gateway: }
            ip addr add dev $NICGUESS $v4addr/$v4plen
            if [ "$v4gw" = "null" ]; then
                v4gw=""
            fi
            if [ ! -z "$v4gw" ]; then
                ip route add default via $v4gw
            fi
            v4nm=$(grep ipv4_netmask: $tcfg)
            v4nm=${v4nm#ipv4_netmask: }
            DETECTED=0
            for dsrv in $deploysrvs; do
                if curl --capath /tls/ -s --connect-timeout 3 https://$dsrv/confluent-public/ > /dev/null; then
                    rm /run/NetworkManager/system-connections/*
                    /usr/libexec/nm-initrd-generator ip=$v4addr::$v4gw:$v4nm:$hostname:$NICGUESS:none
                    DETECTED=1
                    ifname=$NICGUESS
                    break
                fi
            done
            if [ ! -z "$v4gw" ]; then
                ip route del default via $v4gw
            fi
            ip addr flush dev $NICGUESS
            if [ $DETECTED = 1 ]; then
                break
            fi
        fi
    done
    for NICGUESS in $(ip link|grep LOWER_UP|grep -v LOOPBACK| awk '{print $2}' | sed -e 's/:$//'); do
        ip addr flush dev $NICGUESS
        ip link set $NICGUESS down
    done
    NetworkManager --configure-and-quit=initrd --no-daemon
    hmackeyfile=/tmp/cnflnthmackeytmp
    echo -n $(grep ^apitoken: cnflnt.yml|awk '{print $2}') > $hmackeyfile
    cd -
    umount $tmnt
    passfile=/tmp/cnflnttmppassfile
    passcrypt=/tmp/cnflntcryptfile
    hmacfile=/tmp/cnflnthmacfile
    ln -s /opt/confluent/bin/clortho /opt/confluent/bin/genpasshmac
    /opt/confluent/bin/genpasshmac $passfile $passcrypt $hmacfile $hmackeyfile
    echo 'NODENAME: '$nodename > /etc/confluent/confluent.info
    for deploysrv in $deploysrvs; do
        echo 'MANAGER: '$deploysrv >> /etc/confluent/confluent.info
    done
    for deployer in $deploysrvs; do
        if curl --capath /tls/ -f -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_CRYPTHMAC: $(cat $hmacfile)" -d@$passcrypt -k https://$deployer/confluent-api/self/registerapikey; then
            cp $passfile /etc/confluent/confluent.apikey
            confluent_apikey=$(cat /etc/confluent/confluent.apikey)
            curl --capath /tls/ -sf -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $confluent_apikey" https://$deployer/confluent-api/self/deploycfg2 > /etc/confluent/confluent.deploycfg
            confluent_profile=$(grep ^profile: /etc/confluent/confluent.deploycfg)
            confluent_profile=${confluent_profile#profile: }
            mgr=$deployer
            break
        fi
    done
fi
cd /sys/class/net
if ! grep MANAGER: /etc/confluent/confluent.info; then
    confluentsrv=$(getarg confluent)
    if [ ! -z "$confluentsrv" ]; then
        mgr=$confluentsrv
        if [[ "$confluentsrv" = *":"* ]]; then
            mgr="[$mgr]"
            confluenthttpsrv=[$confluentsrv]
            /usr/libexec/nm-initrd-generator ip=:dhcp6
        else
            confluenthttpsrv=$confluentsrv
            /usr/libexec/nm-initrd-generator ip=:dhcp
        fi
        NetworkManager --configure-and-quit=initrd --no-daemon
        myids=uuid=$(cat /sys/devices/virtual/dmi/id/product_uuid)
        for mac in $(ip -br link|grep -v LOOPBACK|awk '{print $3}'); do
            myids=$myids"/mac="$mac
        done
        myname=$(curl --capath /tls/ -sH "CONFLUENT_IDS: $myids" https://$confluenthttpsrv/confluent-api/self/whoami)
        if [ ! -z "$myname" ]; then
            echo NODENAME: $myname > /etc/confluent/confluent.info
            echo MANAGER: $confluentsrv >> /etc/confluent/confluent.info
            echo EXTMGRINFO: $confluentsrv'||1' >> /etc/confluent/confluent.info
        fi
    fi
    while ! grep ^EXTMGRINFO: /etc/confluent/confluent.info | awk -F'|' '{print $3}' | grep 1 >& /dev/null && [ "$TRIES" -lt 60 ]; do
        TRIES=$((TRIES + 1))
        for currif in *; do
            echo 0 > /proc/sys/net/ipv6/conf/${currif}/autoconf
            ip link set $currif up
        done
        /opt/confluent/bin/copernicus -t > /etc/confluent/confluent.info
    done
    grep ^EXTMGRINFO: /etc/confluent/confluent.info || return 0  # Do absolutely nothing if no data at all yet
fi
cd /
echo -n "" > /tmp/confluent.initq
# restart cmdline
echo -n "" > /etc/cmdline.d/01-confluent.conf

nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
#TODO: blkid --label <whatever> to find mounted api

cat /tls/*.pem > /etc/confluent/ca.pem
autocons=$(cat /tmp/01-autocons.devnode)
errout=""
if [ ! -z "$autocons" ]; then
    errout="-e $autocons"
fi
while ! confluentpython /opt/confluent/bin/apiclient $errout /confluent-api/self/deploycfg2 > /etc/confluent/confluent.deploycfg; do
        sleep 10
done
ifidx=$(cat /tmp/confluent.ifidx 2> /dev/null)
if [ -z "$ifname" ]; then
    if [ ! -z "$ifidx" ]; then
        ifname=$(ip link |grep ^$ifidx:|awk '{print $2}')
        ifname=${ifname%:}
        ifname=${ifname%@*}
        echo $ifname > /tmp/net.ifaces
    else
        ip -br a|grep UP|awk '{print $1}' > /tmp/net.ifaces
        ifname=$(cat /tmp/net.ifaces)
    fi
fi

dnsdomain=$(grep ^dnsdomain: /etc/confluent/confluent.deploycfg)
dnsdomain=${dnsdomain#dnsdomain: }
hostname=$nodename
if [ ! -z "$dnsdomain" ] && [ "$dnsdomain" != "null" ]; then
    hostname=$hostname.$dnsdomain
fi
v6cfg=$(grep ^ipv6_method: /etc/confluent/confluent.deploycfg)
v6cfg=${v6cfg#ipv6_method: }
v4cfg=$(grep ^ipv4_method: /etc/confluent/confluent.deploycfg)
v4cfg=${v4cfg#ipv4_method: }
if [ "$v4cfg" = "static" ] || [ "$v4cfg" = "dhcp" ]; then
    mgr=$(grep ^deploy_server: /etc/confluent/confluent.deploycfg)
    mgr=${mgr#deploy_server: }
fi
if [ -z "$mgr" ]; then
    mgr=$(grep ^deploy_server_v6: /etc/confluent/confluent.deploycfg)
    mgr=${mgr#deploy_server_v6: }
    mgr="[$mgr]"
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
            /opt/confluent/bin/autocons -c > /dev/null
            cp /tmp/01-autocons.conf /etc/cmdline.d/
        else
            echo "Unable to automatically detect requested text console"
        fi
fi

. /etc/os-release
if [ "$ID" = "dracut" ]; then
    ID=$(echo $PRETTY_NAME|awk '{print $1}')
    VERSION_ID=$(echo $VERSION|awk '{print $1}')
    if [ "$ID" = "Oracle" ]; then
        ID=OL
    elif [ "$ID" = "Red" ]; then
        ID=RHEL
    fi
fi
ISOSRC=$(blkid -t TYPE=iso9660|grep -Ei ' LABEL="'$ID-$VERSION_ID|sed -e s/:.*//)
if [ -z "$ISOSRC" ]; then
    echo inst.repo=$proto://$mgr/confluent-public/os/$profilename/distribution >> /etc/cmdline.d/01-confluent.conf
    root=anaconda-net:$proto://$mgr/confluent-public/os/$profilename/distribution
    export root
else
    echo inst.repo=cdrom:$ISOSRC >> /etc/cmdline.d/01-confluent.conf
fi
echo inst.ks=$proto://$mgr/confluent-public/os/$profilename/kickstart >> /etc/cmdline.d/01-confluent.conf
kickstart=$proto://$mgr/confluent-public/os/$profilename/kickstart
export kickstart
autoconfigmethod=$(grep ipv4_method /etc/confluent/confluent.deploycfg)
autoconfigmethod=${autoconfigmethod#ipv4_method: }
if [ "$autoconfigmethod" = "dhcp" ]; then
    echo ip=$ifname:dhcp >>  /etc/cmdline.d/01-confluent.conf
elif [ "$autoconfigmethod" = "static" ]; then
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
fi
nameserversec=0
v4dns=0
v6dns=0
while read -r entry; do
    if [ $nameserversec = 1 ]; then
        if [[ $entry == "-"* ]] && [[ $entry != "- ''" ]]; then
            echo nameserver=${entry#- } >> /etc/cmdline.d/01-confluent.conf
            [[ "$entry" == *:* ]] && v6dns=1
            [[ "$entry" == *.* ]] && v4dns=1
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
    if [ ! -z "$dnsdomain" ] && [ "$dnsdomain" != "null" ]; then
        grep -v ^dns-search= /run/NetworkManager/system-connections/$ifname.nmconnection > /run/NetworkManager/system-connections/$ifname.nmconnection.new
        mv /run/NetworkManager/system-connections/$ifname.nmconnection.new /run/NetworkManager/system-connections/$ifname.nmconnection
        if [ "$v4dns" = 1 ]; then
            awk '/^\[ipv4\]/ {print;print "dns-search='"$dnsdomain"'";next}1' /run/NetworkManager/system-connections/$ifname.nmconnection > /run/NetworkManager/system-connections/$ifname.nmconnection.new
        else
            awk '/^\[ipv4\]/ {print;print "dns-search=";next}1' /run/NetworkManager/system-connections/$ifname.nmconnection > /run/NetworkManager/system-connections/$ifname.nmconnection.new
        fi
        mv /run/NetworkManager/system-connections/$ifname.nmconnection.new /run/NetworkManager/system-connections/$ifname.nmconnection
        if [ "$v6dns" = 1 ]; then
            awk '/^\[ipv6\]/ {print;print "dns-search='"$dnsdomain"'";next}1' /run/NetworkManager/system-connections/$ifname.nmconnection > /run/NetworkManager/system-connections/$ifname.nmconnection.new
        else
            awk '/^\[ipv6\]/ {print;print "dns-search=";next}1' /run/NetworkManager/system-connections/$ifname.nmconnection > /run/NetworkManager/system-connections/$ifname.nmconnection.new
        fi
        mv /run/NetworkManager/system-connections/$ifname.nmconnection.new /run/NetworkManager/system-connections/$ifname.nmconnection
        chmod 600 /run/NetworkManager/system-connections/$ifname.nmconnection
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
for NICGUESS in $(ip link|grep LOWER_UP|grep -v LOOPBACK| awk '{print $2}' | sed -e 's/:$//'); do
    ip addr flush dev $NICGUESS
    ip link set $NICGUESS down
done

