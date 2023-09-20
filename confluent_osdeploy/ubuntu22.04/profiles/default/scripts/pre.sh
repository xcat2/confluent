#!/bin/bash
deploycfg=/custom-installation/confluent/confluent.deploycfg
mkdir -p /var/log/confluent
mkdir -p /opt/confluent/bin
mkdir -p /etc/confluent
cp /custom-installation/confluent/confluent.info /custom-installation/confluent/confluent.apikey /etc/confluent/
cat /custom-installation/tls/*.pem >> /etc/confluent/ca.pem
cp /custom-installation/confluent/bin/apiclient /opt/confluent/bin
cp $deploycfg /etc/confluent/
(
exec >> /var/log/confluent/confluent-pre.log
exec 2>> /var/log/confluent/confluent-pre.log
chmod 600 /var/log/confluent/confluent-pre.log

cryptboot=$(grep encryptboot: $deploycfg|sed -e 's/^encryptboot: //')
if [ "$cryptboot" != "" ]  && [ "$cryptboot" != "none" ] && [ "$cryptboot" != "null" ]; then
   echo "****Encrypted boot requested, but not implemented for this OS, halting install" > /dev/console
   [ -f '/tmp/autoconsdev' ] && (echo "****Encryptod boot requested, but not implemented for this OS,halting install" >> $(cat /tmp/autoconsdev))
   while :; do sleep 86400; done
fi


cat /custom-installation/ssh/*pubkey > /root/.ssh/authorized_keys
nodename=$(grep ^NODENAME: /custom-installation/confluent/confluent.info|awk '{print $2}')
apikey=$(cat /custom-installation/confluent/confluent.apikey)
for pubkey in /etc/ssh/ssh_host*key.pub; do
    certfile=${pubkey/.pub/-cert.pub}
    keyfile=${pubkey%.pub}
    curl -f -X POST -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $apikey" -d @$pubkey https://$confluent_mgr/confluent-api/self/sshcert > $certfile
    echo HostKey $keyfile >> /etc/ssh/sshd_config.d/confluent.conf
    echo HostCertificate $certfile >> /etc/ssh/sshd_config.d/confluent.conf
done
echo HostbasedAuthentication yes >> /etc/ssh/sshd_config.d/confluent.conf
echo HostbasedUsesNameFromPacketOnly yes >> /etc/ssh/sshd_config.d/confluent.conf
echo IgnoreRhosts no >> /etc/ssh/sshd_config.d/confluent.conf
systemctl restart sshd
mkdir -p /etc/confluent
curl -f https://$confluent_mgr/confluent-public/os/$confluent_profile/scripts/functions > /etc/confluent/functions
. /etc/confluent/functions
run_remote_parts pre.d
curl -f -X POST -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $apikey" https://$confluent_mgr/confluent-api/self/nodelist > /tmp/allnodes
if [ ! -e /tmp/installdisk ]; then
    curl -f https://$confluent_mgr/confluent-public/os/$confluent_profile/scripts/getinstalldisk > /custom-installation/getinstalldisk
    python3 /custom-installation/getinstalldisk
fi
sed -i s!%%INSTALLDISK%%!/dev/$(cat /tmp/installdisk)! /autoinstall.yaml
) &
tail --pid $! -n 0 -F /var/log/confluent/confluent-pre.log > /dev/console

