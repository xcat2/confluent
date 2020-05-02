cp -a /root/.ssh /target/root/
mkdir -p /target/etc/confluent/ssh/sshd_config.d/
cp /custom-installation/confluent/* /target/etc/confluent/
for i in /custom-installation/ssh/*.ca; do
    echo '@cert-authority *' $(cat $i) >> /target/etc/ssh/ssh_known_hosts
done

cp -a /etc/ssh/ssh_host* /target/etc/confluent/ssh/
cp -a /etc/ssh/sshd_config.d/confluent.conf /target/etc/confluent/ssh/sshd_config.d/
sshconf=/target/etc/ssh/ssh_config
if [ -d /target/etc/ssh/ssh_config.d/ ]; then
    sshconf=/target/etc/ssh/ssh_config.d/01-confluent.conf
fi
echo 'Host *' >> $sshconf
echo '    HostbasedAuthentication yes' >> $sshconf
echo '    EnableSSHKeysign yes' >> $sshconf
echo '    HostbasedKeyTypes *ed25519*' >> $sshconf

cp /custom-installation/firstboot.sh /target/etc/confluent/firstboot.sh
cp /tmp/allnodes /target/root/.shosts
cp /tmp/allnodes /target/etc/ssh/shosts.equiv
