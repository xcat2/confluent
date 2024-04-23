get_remote_apikey() {
    while [ -z "$confluent_apikey" ]; do
        /opt/confluent/bin/clortho $nodename $confluent_mgr > /etc/confluent/confluent.apikey
        if grep ^SEALED: /etc/confluent/confluent.apikey > /dev/null; then
            # we don't support remote sealed api keys anymore
            echo > /etc/confluent/confluent.apikey
        fi
        confluent_apikey=$(cat /etc/confluent/confluent.apikey)
        if [ -z "$confluent_apikey" ]; then
            echo "Unable to acquire node api key, set deployment.apiarmed=once on node '$nodename', retrying..."
            if [ ! -z "$autoconsdev" ]; then echo "Unable to acquire node api key, set deployment.apiarmed=once on node '$nodename', retrying..." > $autoconsdev; fi
            sleep 10
        elif [ -c /dev/tpmrm0 ]; then
            tmpdir=$(mktemp -d)
            cd $tmpdir
            tpm2_startauthsession --session=session.ctx
            tpm2_policypcr -Q --session=session.ctx --pcr-list="sha256:15" --policy=pcr15.sha256.policy
            tpm2_createprimary -G ecc -Q --key-context=prim.ctx
            (echo -n "CONFLUENT_APIKEY:";cat /etc/confluent/confluent.apikey) | tpm2_create -Q --policy=pcr15.sha256.policy --public=data.pub --private=data.priv -i - -C prim.ctx
            tpm2_load -Q --parent-context=prim.ctx --public=data.pub --private=data.priv --name=confluent.apikey --key-context=data.ctx
            tpm2_evictcontrol -Q -c data.ctx
            tpm2_flushcontext session.ctx
            cd - > /dev/null
            rm -rf $tmpdir
        fi
    done
}
. /lib/dracut-lib.sh
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
    autoconsdev=${autocons%,*}
    autocons=${autocons##*/}
    echo "Automatic console configured for $autocons"
fi
echo "Initializing confluent diskless environment"
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
oldumask=$(umask)
umask 0077
tpmdir=$(mktemp -d)
cd $tpmdir
lasthdl=""
if [ -c /dev/tpmrm0 ]; then
    for hdl in $(tpm2_getcap handles-persistent|awk '{print $2}'); do
        tpm2_startauthsession --policy-session --session=session.ctx
        tpm2_policypcr -Q --session=session.ctx --pcr-list="sha256:15" --policy=pcr15.sha256.policy
        unsealeddata=$(tpm2_unseal --auth=session:session.ctx -Q -c $hdl 2>/dev/null)
        tpm2_flushcontext session.ctx
        if [[ $unsealeddata == "CONFLUENT_APIKEY:"* ]]; then
            confluent_apikey=${unsealeddata#CONFLUENT_APIKEY:}
            echo $confluent_apikey > /etc/confluent/confluent.apikey
            if [ -n "$lasthdl" ]; then
                tpm2_evictcontrol -c $lasthdl
            fi
            lasthdl=$hdl
        fi
    done
fi
cd - > /dev/null
rm -rf $tpmdir
touch /etc/confluent/confluent.info
cd /sys/class/net
touch /etc/confluent/confluent.info
confluentsrv=$(getarg confluent)
DIDDHCP=0
if [ ! -z "$confluentsrv" ]; then
    for i in *; do
        ip link set $i up
    done
    if [[ "$confluentsrv" = *":"* ]]; then
        confluenthttpsrv=[$confluentsrv]
        /usr/libexec/nm-initrd-generator ip=:dhcp6
    else
        confluenthttpsrv=$confluentsrv
        ifname=$(ip -br link|grep LOWER_UP|grep -v UNKNOWN|head -n 1|awk '{print $1}')
        echo -n "Attempting to use dhcp to bring up $ifname..."
        dhclient $ifname
        while ! ip -br addr show dev $ifname | grep \\. > /dev/null; do
            echo -n "Still waiting for IPv4 address on: "
            ip -br link show dev $ifname 
            sleep 1
        done
        echo -n "Complete: "
        ip -br addr show dev $ifname
        DIDDHCP=1
    fi
    myids=uuid=$(cat /sys/devices/virtual/dmi/id/product_uuid)
    for mac in $(ip -br link|grep -v LOOPBACK|awk '{print $3}'); do
        myids=$myids"/mac="$mac
    done
    myname=$(curl -sH "CONFLUENT_IDS: $myids" https://$confluenthttpsrv/confluent-api/self/whoami)
    if [ ! -z "$myname" ]; then
        echo NODENAME: $myname > /etc/confluent/confluent.info
        echo MANAGER: $confluentsrv >> /etc/confluent/confluent.info
        echo EXTMGRINFO: $confluentsrv'||1' >> /etc/confluent/confluent.info
    fi
fi
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
confluent_mgr=$(grep '^EXTMGRINFO:.*1$' /etc/confluent/confluent.info | head -n 1 | awk -F': ' '{print $2}' | awk -F'|' '{print $1}')
if [ -z "$confluent_mgr" ]; then
    confluent_mgr=$(grep ^MANAGER: /etc/confluent/confluent.info|head -n 1 | awk '{print $2}')
fi
if [[ $confluent_mgr == *%* ]]; then
    echo $confluent_mgr | awk -F% '{print $2}' > /tmp/confluent.ifidx
    ifidx=$(cat /tmp/confluent.ifidx)
    ifname=$(ip link |grep ^$ifidx:|awk '{print $2}')
    ifname=${ifname%:}
fi

ready=0
while [ $ready = "0" ]; do
    get_remote_apikey
    if [[ $confluent_mgr == *:* ]] && [[ $confluent_mgr != "["* ]]; then
        confluent_mgr="[$confluent_mgr]"
    fi
    tmperr=$(mktemp)
    curl -sSf -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $confluent_apikey" https://$confluent_mgr/confluent-api/self/deploycfg2 > /etc/confluent/confluent.deploycfg 2> $tmperr
    if grep 401 $tmperr > /dev/null; then
        confluent_apikey=""
        if [ -n "$lasthdl" ]; then
            tpm2_evictcontrol -c $lasthdl
        fi
        confluent_mgr=${confluent_mgr#[}
        confluent_mgr=${confluent_mgr%]}
    elif grep 'SSL' $tmperr > /dev/null; then
        confluent_mgr=${confluent_mgr#[}
        confluent_mgr=${confluent_mgr%]}
    	echo 'Failure establishing TLS conneection to '$confluent_mgr' (try `osdeploy initialize -t` on the deployment server)'
	if [ ! -z "$autoconsdev" ]; then echo 'Failure establishing TLS conneection to '$confluent_mgr' (try `osdeploy initialize -t` on the deployment server)' > $autoconsdev; fi
    	sleep 10
    else
        ready=1
    fi
    rm $tmperr
done
if [ ! -z "$autocons" ] && grep "textconsole: true" /etc/confluent/confluent.deploycfg > /dev/null; then /opt/confluent/bin/autocons -c > /dev/null; fi
if [ -c /dev/tpmrm0 ]; then
    tpm2_pcrextend 15:sha256=2fbe96c50dde38ce9cd2764ddb79c216cfbcd3499568b1125450e60c45dd19f2
fi
umask $oldumask
mkdir -p /run/NetworkManager/system-connections
cat > /run/NetworkManager/system-connections/$ifname.nmconnection << EOC
[connection]
EOC
echo id=${ifname} >> /run/NetworkManager/system-connections/$ifname.nmconnection
echo uuid=$(uuidgen) >> /run/NetworkManager/system-connections/$ifname.nmconnection
linktype=$(ip link show dev ${ifname}|grep link/|awk '{print $1}')
if [ "$linktype" = link/infiniband ]; then
	linktype="infiniband"
else
	linktype="ethernet"
fi
echo type=$linktype >> /run/NetworkManager/system-connections/$ifname.nmconnection

cat >> /run/NetworkManager/system-connections/$ifname.nmconnection << EOC
autoconnect-retries=1
EOC
echo interface-name=$ifname >> /run/NetworkManager/system-connections/$ifname.nmconnection
cat >> /run/NetworkManager/system-connections/$ifname.nmconnection << EOC
multi-connect=1
permissions=
wait-device-timeout=60000

EOC
autoconfigmethod=$(grep ^ipv4_method: /etc/confluent/confluent.deploycfg |awk '{print $2}')
auto6configmethod=$(grep ^ipv6_method: /etc/confluent/confluent.deploycfg |awk '{print $2}')
if [ "$autoconfigmethod" = "dhcp" ]; then
    if [ "$DIDDHCP" = "0" ]; then
        echo -n "Attempting to use dhcp to bring up $ifname..."
        dhclient $ifname
        while ! ip -br addr show dev $ifname | grep \\. > /dev/null; do
            echo -n "Still waiting for IPv4 address on: "
            ip -br link show dev $ifname 
            sleep 1
        done
        echo -n "Complete: "
        ip -br addr show dev $ifname
    fi
    confluent_mgr=$(grep ^deploy_server: /etc/confluent/confluent.deploycfg| awk '{print $2}')
elif [ "$autoconfigmethod" = "static" ]; then
    confluent_mgr=$(grep ^deploy_server: /etc/confluent/confluent.deploycfg| awk '{print $2}')
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
    echo '[ipv4]' >> /run/NetworkManager/system-connections/$ifname.nmconnection
    echo address1=$v4addr/$v4nm >> /run/NetworkManager/system-connections/$ifname.nmconnection
    if [ ! -z "$v4gw" ]; then
        echo gateway=$v4gw >> /run/NetworkManager/system-connections/$ifname.nmconnection
    fi
    nameserversec=0
    nameservers=""
    while read -r entry; do
        if [ $nameserversec = 1 ]; then
            if [[ $entry == "-"*.* ]]; then
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

EOC
elif [ "$auto6configmethod" = "static" ]; then
    confluent_mgr=$(grep ^deploy_server_v6: /etc/confluent/confluent.deploycfg| awk '{print $2}')
    v6addr=$(grep ^ipv6_address: /etc/confluent/confluent.deploycfg)
    v6addr=${v6addr#ipv6_address: }
    v6gw=$(grep ^ipv6_gateway: /etc/confluent/confluent.deploycfg)
    v6gw=${v6gw#ipv6_gateway: }
    if [ "$v6gw" = "null" ]; then
        v6gw=""
    fi
    v6nm=$(grep ^ipv6_prefix: /etc/confluent/confluent.deploycfg)
    v6nm=${v6nm#ipv6_prefix: }
    echo "Setting up $ifname as static at $v6addr/$v6nm"
    ip addr add dev $ifname $v6addr/$v6nm
    
    cat >> /run/NetworkManager/system-connections/$ifname.nmconnection << EOC
[ipv4]
dhcp-timeout=90
dhcp-vendor-class-identifier=anaconda-Linux
method=disabled

[ipv6]
addr-gen-mode=eui64
method=manual
may-fail=false
EOC
    echo address1=$v6addr/$v6nm >> /run/NetworkManager/system-connections/$ifname.nmconnection
    if [ ! -z "$v6gw" ]; then
        ip route add default via $v6gw
        echo gateway=$v6gw >> /run/NetworkManager/system-connections/$ifname.nmconnection
    fi
    nameserversec=0
    nameservers=""
    while read -r entry; do
        if [ $nameserversec = 1 ]; then
            if [[ $entry == "-"*:* ]]; then
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
fi
echo '[proxy]' >> /run/NetworkManager/system-connections/$ifname.nmconnection
chmod 600 /run/NetworkManager/system-connections/*.nmconnection
confluent_websrv=$confluent_mgr
if [[ $confluent_websrv == *:* ]] && [[ $confluent_websrv != "["* ]]; then
    confluent_websrv="[$confluent_websrv]"
fi
echo -n "Initializing ssh..."
ssh-keygen -A
for pubkey in /etc/ssh/ssh_host*key.pub; do
    certfile=${pubkey/.pub/-cert.pub}
    privfile=${pubkey%.pub}
    curl -sf -X POST -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $confluent_apikey" -d @$pubkey  https://$confluent_websrv/confluent-api/self/sshcert > $certfile
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
mkdir -p /etc/confluent
curl -sf https://$confluent_websrv/confluent-public/os/$confluent_profile/scripts/functions > /etc/confluent/functions
. /etc/confluent/functions
source_remote imageboot.sh
