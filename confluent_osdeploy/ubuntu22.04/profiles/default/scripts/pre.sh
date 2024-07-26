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
export nodename confluent_profile confluent_mgr
curl -f https://$confluent_mgr/confluent-public/os/$confluent_profile/scripts/functions > /etc/confluent/functions
. /etc/confluent/functions
run_remote_parts pre.d
curl -f -X POST -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $apikey" https://$confluent_mgr/confluent-api/self/nodelist > /tmp/allnodes
if [ ! -e /tmp/installdisk ]; then
    curl -f https://$confluent_mgr/confluent-public/os/$confluent_profile/scripts/getinstalldisk > /custom-installation/getinstalldisk
    python3 /custom-installation/getinstalldisk
fi
sed -i s!%%INSTALLDISK%%!/dev/$(cat /tmp/installdisk)! /autoinstall.yaml
if [ "$cryptboot" != "" ]  && [ "$cryptboot" != "none" ] && [ "$cryptboot" != "null" ]; then
    if ! grep '#CRYPTBOOT' /autoinstall.yaml > /dev/null; then
        echo "****Encrypted boot requested, but the user-data does not have a hook to enable,halting install" > /dev/console
        [ -f '/tmp/autoconsdev' ] && (echo "****Encryptod boot requested, but the user-data does not have a hook to enable,halting install" >> $(cat /tmp/autoconsdev))
        while :; do sleep 86400; done
    fi
    lukspass=$(head -c 66 < /dev/urandom |base64 -w0)
    sed -i s!%%CRYPTPASS%%!$lukspass! /autoinstall.yaml
    sed -i s!'#CRYPTBOOT'!! /autoinstall.yaml
    echo -n $lukspass > /etc/confluent_lukspass

fi
) &
tail --pid $! -n 0 -F /var/log/confluent/confluent-pre.log > /dev/console

