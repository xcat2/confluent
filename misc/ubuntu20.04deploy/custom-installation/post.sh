cp -a /root/.ssh /target/root/
mkdir -p /target/etc/confluent/ssh/sshd_config.d/
cp /custom-installation/confluent/* /target/etc/confluent/
cp -a /etc/ssh/ssh_host* /target/etc/confluent/ssh/
cp -a /etc/ssh/sshd_config.d/confluent.conf /target/etc/confluent/ssh/sshd_config.d/
cp /custom-installation/firstboot.sh /target/etc/confluent/firstboot.sh
