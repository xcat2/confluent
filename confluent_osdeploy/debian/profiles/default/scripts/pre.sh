anna-install openssh-server-udeb
mkdir -p ~/.ssh/
cat /ssh/*pubkey > ~/.ssh/authorized_keys
ssh-keygen -A
mgr=$(grep ^MANAGER:.*\\. /etc/confluent/confluent.info|head -n 1|cut -d: -f 2|sed -e 's/ //')
nodename=$(grep ^NODENAME: /etc/confluent/confluent.info|head -n 1|cut -d: -f 2|sed -e 's/ //')
apikey=$(cat /etc/confluent/confluent.apikey)
for pubkey in /etc/ssh/ssh_host*key.pub; do
    certfile=${pubkey%.pub}-cert.pub
    keyfile=${pubkey%.pub}
    wget --post-file=$pubkey --header='CONFLUENT_NODENAME: '$nodename --header="CONFLUENT_APIKEY: $apikey" https://$mgr/confluent-api/self/sshcert -O $certfile
    echo HostKey $keyfile >> /etc/ssh/sshd_config
    echo HostCertificate $certfile >> /etc/ssh/sshd_config
done

echo sshd:x:939:939::/: >> /etc/passwd
/usr/sbin/sshd

