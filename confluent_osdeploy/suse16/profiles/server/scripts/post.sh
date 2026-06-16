#!/bin/bash

# This script runs at the end of install in the installed system
# but still under the installer kernel.

# This is a good place to run most customizations that do not have any
# dependency upon the install target kernel being active.

# If there are dependencies on the kernel (drivers or special filesystems)
# then firstboot.sh would be the script to customize.

mkdir -p /var/log/confluent
chmod 700 /var/log/confluent
exec >> /var/log/confluent/confluent-post.log
exec 2>> /var/log/confluent/confluent-post.log
chmod 600 /var/log/confluent/confluent-post.log
confluent_mgr=$(grep ^deploy_server: /etc/confluent/confluent.deploycfg|awk '{print $2}')
if [ -z "$confluent_mgr" ] || [ "$confluent_mgr" = "none" ] || [ "$confluent_mgr" = "null" ]; then
    confluent_mgr=$(grep ^deploy_server_v6: /etc/confluent/confluent.deploycfg|awk '{print $2}')
fi
confluent_profile=$(grep ^profile: /etc/confluent/confluent.deploycfg|sed -e 's/^profile: //')
nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
confluent_apikey=$(cat /etc/confluent/confluent.apikey)

chmod 700 /etc/confluent
chmod og-rwx /etc/confluent/*


export confluent_mgr confluent_profile nodename
. /etc/confluent/functions

# This will induce server side processing of the syncfile contents if
# present
run_remote_python syncfileclient

run_remote post.custom

# Also, scripts may be placed into 'post.d', e.g. post.d/01-runfirst.sh, post.d/02-runsecond.sh
run_remote_parts post.d

# Induce execution of remote configuration, e.g. ansible plays in ansible/post.d/
run_remote_config post.d

# stage firstboot, agama could be used, but we can stage it here to keep impact on agama json minimal
mkdir -p /opt/confluent/bin
python3 /opt/confluent/bin/apiclient /confluent-public/os/$confluent_profile/scripts/firstboot.sh > /opt/confluent/bin/firstboot.sh
cat >/etc/systemd/system/confluent-firstboot.service <<EOF
[Unit]
Description=First Boot Process
Requires=network-online.target
After=network-online.target

[Service]
ExecStart=/opt/confluent/bin/firstboot.sh

[Install]
WantedBy=multi-user.target
EOF

chmod +x /opt/confluent/bin/firstboot.sh
systemctl enable confluent-firstboot
systemctl enable sshd
python3 /opt/confluent/bin/apiclient /confluent-api/self/updatestatus -d 'status: staged'

