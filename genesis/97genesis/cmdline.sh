root=1
rootok=1
netroot=xcat
clear
echo PS1="'"'[genesis running on \H \w]$ '"'" >> ~/.bashrc
echo PS1="'"'[genesis running on \H \w]$ '"'" >> ~/.bash_profile
mkdir -p /etc/ssh
mkdir -p /var/tmp/
mkdir -p /var/empty/sshd
sed -i '/^root:x/d' /etc/passwd
echo root:x:0:0::/:/bin/bash >> /etc/passwd
echo sshd:x:30:30:SSH User:/var/empty/sshd:/sbin/nologin >> /etc/passwd
/usr/lib/systemd/systemd-udevd --daemon
udevadm trigger
udevadm trigger --type=devices --action=add
udevadm settle
tmux -L console new-session /bin/rungenesis
