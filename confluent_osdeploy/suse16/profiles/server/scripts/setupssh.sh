#!/bin/bash
# Carry over install-time ssh material into installed system

mkdir -p /mnt/root/.ssh/
chmod 700 /mnt/root/.ssh/
cp /root/.ssh/authorized_keys /mnt/root/.ssh/
chmod 600 /mnt/root/.ssh/authorized_keys
cp /etc/ssh/ssh*key* /mnt/etc/ssh/
mkdir -p /mnt/etc/ssh/sshd_config.d/
# pre.sh put the host certificates confluent signed into this drop-in
cp /etc/ssh/sshd_config.d/20_hostkeys.conf /mnt/etc/ssh/sshd_config.d/
# the initramfs wrote the confluent CA into the installer's known hosts
cp /etc/ssh/ssh_known_hosts /mnt/etc/ssh/

# Enable ~/.shosts, for the sake of root user, who is forbidden from using shosts.equiv
cat >> /mnt/etc/ssh/sshd_config.d/90-confluent.conf << EOF
IgnoreRhosts no
HostbasedAuthentication yes
HostbasedUsesNameFromPacketOnly yes
EOF

sshconf=/mnt/etc/ssh/ssh_config
if [ -d /mnt/etc/ssh/ssh_config.d/ ]; then
    sshconf=/mnt/etc/ssh/ssh_config.d/01-confluent.conf
fi
echo Host '*' >> $sshconf
echo "    HostbasedAuthentication yes" >> $sshconf
echo "    EnableSSHKeysign yes" >> $sshconf
# Limit the attempts of using host key. This prevents client from using 3 or 4
# authentication attempts through host based attempts
echo "    HostbasedKeyTypes *ed25519*" >> $sshconf

# In SUSE platform, setuid for ssh-keysign is required for host based,
# and also must be opted into. 16 moved the helper to libexec.
keysign=/usr/libexec/ssh/ssh-keysign
if [ ! -e /mnt$keysign ]; then
    keysign=/usr/lib/ssh/ssh-keysign
fi
echo $keysign root:root 4711 >> /mnt/etc/permissions.local
chmod 4711 /mnt$keysign

# Download list of nodes from confluent, and put it into shosts.equiv (for most users) and .shosts (for root)
python3 /opt/confluent/bin/apiclient /confluent-api/self/nodelist | sed -e 's/^- //' > /mnt/etc/ssh/shosts.equiv
cp /mnt/etc/ssh/shosts.equiv /mnt/root/.shosts
