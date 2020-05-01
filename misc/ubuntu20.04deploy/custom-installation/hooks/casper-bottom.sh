cd /root
cat /tls/*.0 > /root/etc/ssl/certs/ca-certificates.crt
mkdir -p /root/custom-installation/ssh
cp /ssh/* /root/custom-installation/ssh
NODENAME=$(grep ^NODENAME: /custom-installation/confluent/confluent.info|awk '{print $2}')
MGR=$(grep ^MANAGER: /custom-installation/confluent/confluent.info|head -n 1| awk '{print $2}')
oum=$(umask)
umask 077
chroot . custom-installation/confluent/bin/clortho $NODENAME $MGR > /root/custom-installation/confluent/confluent.apikey
MGR=[$MGR]
deploycfg=/root/custom-installation/confluent/confluent.deploycfg
chroot . usr/bin/curl -f -H "CONFLUENT_NODENAME: $NODENAME" -H "CONFLUENT_APIKEY: $(cat /root//custom-installation/confluent/confluent.apikey)" https://${MGR}/confluent-api/self/deploycfg > $deploycfg
umask $oum
nic=$(grep ^MANAGER /custom-installation/confluent/confluent.info|grep fe80::|sed -e s/.*%//|head -n 1)
nic=$(ip link |grep ^$nic:|awk '{print $2}')
DEVICE=${nic%:}
ipv4m=$(grep ^ipv4_method $deploycfg|awk '{print$2}')
. /scripts/functions
if [ "$ipv4m" = "dhcp" ]; then
    IP=dhcp
    configure_networking
elif [ "$ipv4m" = "static" ]; then
    v4addr=$(grep ^ipv4_address: $deploycfg)
    v4addr=${v4addr#ipv4_address: }
    v4gw=$(grep ^ipv4_gateway: $deploycfg)
    v4gw=${v4gw#ipv4_gateway: }
    if [ "$v4gw" = "null" ]; then
        v4gw=""
    fi
    v4nm=$(grep ipv4_netmask: $deploycfg)
    v4nm=${v4nm#ipv4_netmask: }
    dns=$(grep -A1 ^nameservers: $deploycfg|head -n 2|tail -n 1|sed -e 's/^- //'|sed -e "s/''//")

    IP=$v4addr::$v4gw:$v4nm:$nodename:$DEVICE:none:$dns::
    configure_networking
else
    IP=off
fi
ipv4s=$(grep ^ipv4_server $deploycfg|awk '{print $2}')
osprofile=$(cat /custom-installation/confluent/osprofile)
fcmdline='quiet autoinstall ds=nocloud-net;s=https://'${ipv4s}'/confluent-public/os/'${osprofile}'/autoinstall/'
cons=$(cat /custom-installation/autocons.info)
if [ ! -z "$cons" ]; then
    echo "Installation will proceed on graphics console, autoconsole cannot work during install for Ubuntu" > ${cons%,*}
    #fcmdline="$fcmdline console=${cons#/dev/}"
elif grep console= /proc/cmdline; then
    fcmdline=$fcmdline" "$(sed -e s/.*console=/console=/ -e 's/ .*//' /proc/cmdline)
fi
echo $fcmdline > /custom-installation/confluent/fakecmdline
/scripts/casper-bottom/58server_network
