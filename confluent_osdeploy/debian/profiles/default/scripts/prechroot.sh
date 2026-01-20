#!/bin/sh
mount -o bind /sys /target/sys
mount -o bind /dev /target/dev
mount -o bind /dev/pts /target/dev/pts
mount -o bind /proc /target/proc
mount -o bind /dev/pts /target/dev/pts
mount -o bind /run /target/run
cp -a /etc/confluent /target/etc/confluent
cp -a /opt/confluent /target/opt/confluent
mv /tmp/post.sh /target/tmp/
cp -a /ssh /tls /target/tmp
cat /tls/*.pem >> /target/etc/confluent/ca.pem
cp -a /etc/ssh/ssh_host_* /target/etc/ssh/
grep HostCertificate /etc/ssh/sshd_config  >> /target/etc/ssh/sshd_config
echo Port 2222 >> /etc/ssh/sshd_config
kill -HUP $(ps |grep -v grep|grep sshd|grep /usr|sed -e s/' root.*//')
cp /tls/* /target/etc/ssl/certs/
cat /tls/*.pem >> /target/etc/ssl/certs/ca-certificates.crt
chroot /target bash /tmp/post.sh
