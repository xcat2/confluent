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
chroot /target bash /tmp/post.sh
