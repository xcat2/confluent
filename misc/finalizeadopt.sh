#!/bin/bash
if ! grep ^HostbasedAuthentication /etc/ssh/sshd_config > /dev/null; then
    echo HostbasedAuthentication yes >> /etc/ssh/sshd_config
    echo HostbasedUsesNameFromPacketOnly yes >> /etc/ssh/sshd_config
    echo IgnoreRhosts no >> /etc/ssh/sshd_config
fi
for certfile in /etc/ssh/*cert*; do
	if ! grep $certfile /etc/ssh/sshd_config > /dev/null; then
		echo HostCertificate $certfile >> /etc/ssh/sshd_config
	fi
done
if [ -d /etc/ssh/ssh_config.d/ ]; then
	cat > /etc/ssh/ssh_config.d/01-confluent.conf << EOF
Host *
    HostbasedAuthentication yes
    EnableSSHKeysign yes
    HostbasedKeyTypes *ed25519*
EOF
else
    if ! grep EnableSSHKeysign /etc/ssh/ssh_config > /dev/null; then
	cat >> /etc/ssh/ssh_config << EOF
Host *
    HostbasedAuthentication yes
    EnableSSHKeysign yes
#    HostbasedKeyTypes *ed25519*
EOF
  fi
fi
restorecon -r /etc/ssh
restorecon /root/.shosts

systemctl restart sshd
