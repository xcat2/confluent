#!/bin/sh

rm /etc/ssh/*host*key* >& /dev/null
ssh-keygen -A
/usr/libexec/platform-python /etc/confluent/apiclient >& /dev/null
for pubkey in /etc/ssh/ssh_host*key.pub; do
    certfile=${pubkey/.pub/-cert.pub}
    /usr/libexec/platform-python /etc/confluent/apiclient /confluent-api/self/sshcert $pubkey > $certfile
    echo HostCertificate $certfile >> /etc/ssh/sshd_config
done

echo HostbasedAuthentication yes >> /etc/ssh/sshd_config
echo HostbasedUsesNameFromPacketOnly yes >> /etc/ssh/sshd_config
echo IgnoreRhosts no >> /etc/ssh/sshd_config
if [ -d /etc/ssh/ssh_config.d/ ]; then
    sshconf=/etc/ssh/ssh_config.d/01-confluent.conf
fi
echo 'Host *' >> $sshconf
echo '    HostbasedAuthentication yes' >> $sshconf
echo '    EnableSSHKeysign yes' >> $sshconf
echo '    HostbasedKeyTypes *ed25519*' >> $sshconf

curl -Ssf -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $(cat /etc/confluent/confluent.apikey)" https://$mgr/confluent-api/self/nodelist > /tmp/allnodes
cp /tmp/allnodes /etc/ssh/shosts.equiv
cp /tmp/allnodes /root/.shosts
rm /tmp/allnodes

