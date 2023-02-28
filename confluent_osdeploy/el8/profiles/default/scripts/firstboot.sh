#!/bin/sh

# This script is executed on the first boot after install has
# completed. It is best to edit the middle of the file as
# noted below so custom commands are executed before
# the script notifies confluent that install is fully complete.

nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
confluent_apikey=$(cat /etc/confluent/confluent.apikey)
v4cfg=$(grep ^ipv4_method: /etc/confluent/confluent.deploycfg)
v4cfg=${v4cfg#ipv4_method: }
if [ "$v4cfg" = "static" ] || [ "$v4cfg" = "dhcp" ]; then
    confluent_mgr=$(grep ^deploy_server: /etc/confluent/confluent.deploycfg)
    confluent_mgr=${confluent_mgr#deploy_server: }
    confluent_pingtarget=$confluent_mgr
fi
if [ -z "$confluent_mgr" ]; then
    confluent_mgr=$(grep ^deploy_server_v6: /etc/confluent/confluent.deploycfg)
    confluent_mgr=${confluent_mgr#deploy_server_v6: }
    if [ -z "$confluent_mgr" ]; then
        confluent_mgr=$(grep ^deploy_server: /etc/confluent/confluent.deploycfg)
        confluent_mgr=${confluent_mgr#deploy_server: }
        confluent_pingtarget=$confluent_mgr
    else
        confluent_pingtarget=$confluent_mgr
        confluent_mgr="[$confluent_mgr]"
    fi
fi
confluent_profile=$(grep ^profile: /etc/confluent/confluent.deploycfg|awk '{print $2}')
export nodename confluent_mgr confluent_profile
. /etc/confluent/functions
(
exec >> /var/log/confluent/confluent-firstboot.log
exec 2>> /var/log/confluent/confluent-firstboot.log
chmod 600 /var/log/confluent/confluent-firstboot.log
if [ ! -f /etc/confluent/firstboot.ran ]; then
    cat /etc/confluent/tls/*.pem >> /etc/pki/tls/certs/ca-bundle.crt
    confluentpython /root/confignet
    rm /root/confignet
fi


while ! ping -c 1 $confluent_pingtarget >& /dev/null; do
	sleep 1
done


if [ ! -f /etc/confluent/firstboot.ran ]; then
    touch /etc/confluent/firstboot.ran

    run_remote firstboot.custom
    # Firstboot scripts may be placed into firstboot.d, e.g. firstboot.d/01-firstaction.sh, firstboot.d/02-secondaction.sh
    run_remote_parts firstboot.d

    # Induce execution of remote configuration, e.g. ansible plays in ansible/firstboot.d/
    run_remote_config firstboot.d
fi

curl -X POST -d 'status: complete' -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $confluent_apikey" https://$confluent_mgr/confluent-api/self/updatestatus
systemctl disable firstboot
rm /etc/systemd/system/firstboot.service
rm /etc/confluent/firstboot.ran
) &
tail --pid $! -n 0 -F /var/log/confluent/confluent-firstboot.log > /dev/console
