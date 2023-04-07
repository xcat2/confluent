#!/bin/sh
## Use the following option to add additional boot parameters for the
## installed system (if supported by the bootloader installer).
## Note: options passed to the installer will be added automatically.
#d-i debian-installer/add-kernel-opts string [from profile.yaml]
deploycfg=/etc/confluent/confluent.deploycfg
mgr=$(cat /etc/confluent/deployer)

cryptboot=$(grep encryptboot: $deploycfg|sed -e 's/^encryptboot: //')
if [ "$cryptboot" != "" ]  && [ "$cryptboot" != "none" ] && [ "$cryptboot" != "null" ]; then
   echo "****Encrypted boot requested, but not implemented for this OS, halting install" > /dev/console
   [ -f '/tmp/autoconsdev' ] && (echo "****Encryptod boot requested, but not implemented for this OS,halting install" >> $(cat /tmp/autoconsdev))
   while :; do sleep 86400; done
fi
cat > /usr/lib/live-installer.d/confluent-certs << EOF
#!/bin/sh
cp /tls/* /target/etc/ssl/certs/
cat /tls/*.pem >> /target/etc/ssl/certs/ca-certificates.crt
EOF
chmod a+x /usr/lib/live-installer.d/confluent-certs
mkdir -p /.ssh/
cat /ssh/*pubkey > /.ssh/authorized_keys
mkdir -p /etc/ssh
nodename=$(grep ^NODENAME: /etc/confluent/confluent.info|cut -d ' ' -f 2)
apikey=$(cat /etc/confluent/confluent.apikey)
ssh-keygen -A
for pubkey in /etc/ssh/ssh_host*key.pub; do
    certfile=$(echo $pubkey | sed -e s/.pub/-cert.pub/)
    keyfile=${pubkey%.pub}
    wget --header="CONFLUENT_NODENAME: $nodename" --header="CONFLUENT_APIKEY: $apikey" --post-file=$pubkey https://$mgr/confluent-api/self/sshcert -O $certfile --quiet
    echo HostKey $keyfile >> /etc/ssh/sshd_config
    echo HostCertificate $certfile >> /etc/ssh/sshd_config
done
if [ -e /tmp/installdisk ]; then
    instdisk=$(cat /tmp/installdisk)
else
    for blockdev in $(ls /sys/class/block/); do
        shortname=$(basename $blockdev)
        if [ "$shortname" != "${shortname%loop*}" ]; then
            continue
        fi
        udevadm info --query=property /dev/$shortname |grep DEVTYPE=disk > /dev/null || continue # ignore partitions
        udevadm info --query=property /dev/$shortname |grep DM_NAME > /dev/null && continue # not a real disk
        sz=$(cat /sys/block/$shortname/size 2> /dev/null)
        [ -z "$sz" ] && continue
        [ $sz -lt 1048576 ] && continue # Too small
        [ -z "$firstdisk" ] && firstdisk=$shortname
        if udevadm info --query=property /dev/$shortname|grep ID_MODEL=| sed -e s/' '/_/g | grep -iE '(thinksystem_m.2|m.2_nvme_2-bay_raid_kit)' > /dev/null; then
            instdisk=$shortname
            break
        fi
        if udevadm info --query=property /dev/$shortname|grep MD_CONTAINER=imsm; then
            sraid=$sortname
        else
            drv=$(udevadm info -a /dev/sdb|grep DRIVERS==|grep -Ev '""|"sd"' | sed -e s/.*=// -e s/'"'//g)
            if [ "ahci" = "$drv" -a -z "$onbdisk" ]; then
                onbdisk=$shortname
            elif [ "megaraid" = "$drv" -a -z "$rdisk" ]; then
                rdisk=$shortname
            fi
        fi
    done
fi
if [ -z "$instdisk" ]; then
    if [ ! -z "$sraid"]; then
        instdisk=$sraid
    elif [ ! -z "$onbdisk" ]; then
        instdisk=$onbdisk
    elif [ ! -z "$rdisk" ]; then
        instdisk=$rdisk
    else
        instdisk=$firstdisk
    fi
fi
if [ ! -z "$instdisk" ]; then
    debconf-set partman-auto/disk /dev/$instdisk
fi
echo HostbasedAuthentication yes >> /etc/ssh/sshd_config
echo HostbasedUsesNameFromPacketOnly yes >> /etc/ssh/sshd_config
echo IgnoreRhosts no >> /etc/ssh/sshd_config
echo sshd:x:1:1::/run/sshd:/bin/false >> /etc/passwd
/usr/sbin/sshd
wget --header="CONFLUENT_NODENAME: $nodename" --header="CONFLUENT_APIKEY: $apikey" https://$mgr/confluent-api/self/nodelist -O /tmp/allnodes --quiet
#kill -HUP $(ps | grep -v grep | grep /usr/sbin/sshd | sed -e 's/^ *//'|cut -d ' ' -f 1)
#curl -f https://$confluent_mgr/confluent-public/os/$confluent_profile/scripts/getinstalldisk > /tmp/getinstalldisk
#python3 /tmp/getinstalldisk
#sed -i s!%%INSTALLDISK%%!/dev/$(cat /tmp/installdisk)! /autoinstall.yaml
