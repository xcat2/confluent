#!/bin/sh
# if ignition configuration is driving, defer to it
if [ ! -f /config.ign ]; then

    nodename=$(grep ^NODENAME: /etc/confluent/confluent.info | awk '{print $2}')
    confluent_mgr=$(grep ^MANAGER: /etc/confluent/confluent.info| head -n 1| awk '{print $2}' | sed -e s/%/%25/)
    if [[ $confluent_mgr = *:* ]]; then
        confluent_mgr=[$confluent_mgr]
    fi
    rootpassword=$(grep ^rootpassword: /etc/confluent/confluent.deploycfg)
    rootpassword=${rootpassword#rootpassword: }
    if [ "$rootpassword" = "null" ]; then
        rootpassword=""
    fi

    if [ ! -z "$rootpassword" ]; then
        sed -i "s@root:[^:]*:@root:$rootpassword:@" /sysroot/etc/shadow
    fi

    mount -o bind /dev /sysroot/dev
    chroot /sysroot ssh-keygen -A
    umount /sysroot/dev
    for i in  /sysroot/etc/ssh/ssh_host*key.pub; do
        certname=${i/.pub/-cert.pub}
        curl -f -X POST -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $(cat /etc/confluent/confluent.apikey)" -d @$i https://$confluent_mgr/confluent-api/self/sshcert > $certname
        echo HostKey ${i%.pub} | sed -e 's!/sysroot!!' >> /sysroot/etc/ssh/sshd_config
        echo HostCertificate $certname | sed -e 's!/sysroot!!' >> /sysroot/etc/ssh/sshd_config
done
