root=1
rootok=1
netroot=genesis
clear
echo PS1="'"'[genesis running on \H \w]$ '"'" >> ~/.bashrc
echo PS1="'"'[genesis running on \H \w]$ '"'" >> ~/.bash_profile
mkdir -p /etc/ssh
mkdir -p /var/tmp/
mkdir -p /var/empty/sshd
sed -i '/^root:/d' /etc/passwd
echo root:x:0:0::/:/bin/bash >> /etc/passwd
echo sshd:x:30:30:SSH User:/var/empty/sshd:/sbin/nologin >> /etc/passwd
tmux new-session -d sh /opt/confluent/bin/rungenesis
while :; do
	sleep 86400
done
