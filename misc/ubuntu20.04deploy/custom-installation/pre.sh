#!/bin/bash
deploycfg=/custom-installation/confluent/confluent.deploycfg
mgr=$(grep ^ipv4_server $deploycfg|awk '{print $2}')
cat /custom-installation/ssh/*.rootpubkey > /root/.ssh/authorized_keys
nodename=$(grep ^NODENAME: /custom-installation/confluent/confluent.info|awk '{print $2}')
apikey=$(cat /custom-installation/confluent/confluent.apikey)
for pubkey in /etc/ssh/ssh_host*key.pub; do
    certfile=${pubkey/.pub/-cert.pub}
    keyfile=${pubkey%.pub}
    curl -f -X POST -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $apikey" -d @$pubkey https://$mgr/confluent-api/self/sshcert > $certfile
    echo HostKey $keyfile >> /etc/ssh/sshd_config.d/confluent.conf
    echo HostCertificate $certfile >> /etc/ssh/sshd_config.d/confluent.conf
done
systemctl restart sshd
