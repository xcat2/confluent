#!/bin/sh

# This script is executed 'chrooted' into a cloned disk target before rebooting
#

nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
confluent_apikey=$(cat /etc/confluent/confluent.apikey)
confluent_profile=$(grep ^profile: /etc/confluent/confluent.deploycfg|awk '{print $2}')
confluent_mgr=$(grep ^deploy_server_v6: /etc/confluent/confluent.deploycfg|awk '{print $2}')
if [ -z "$confluent_mgr" ] || [ "$confluent_mgr" == "null" ] || ! ping -c 1 $confluent_mgr >& /dev/null; then
    confluent_mgr=$(grep ^deploy_server: /etc/confluent/confluent.deploycfg|awk '{print $2}')
fi
confluent_websrv=$confluent_mgr
if [[ "$confluent_mgr" == *:* ]]; then
    confluent_websrv="[$confluent_mgr]"
fi
export nodename confluent_mgr confluent_profile confluent_websrv
. /etc/confluent/functions
mkdir -p /var/log/confluent
chmod 700 /var/log/confluent
exec >> /var/log/confluent/confluent-post.log
exec 2>> /var/log/confluent/confluent-post.log
chmod 600 /var/log/confluent/confluent-post.log
tail -f /var/log/confluent/confluent-post.log > /dev/console &
logshowpid=$!
curl -f https://$confluent_websrv/confluent-public/os/$confluent_profile/scripts/firstboot.service > /etc/systemd/system/firstboot.service
mkdir -p /opt/confluent/bin
curl -f https://$confluent_websrv/confluent-public/os/$confluent_profile/scripts/firstboot.sh > /opt/confluent/bin/firstboot.sh
chmod +x /opt/confluent/bin/firstboot.sh
systemctl enable firstboot
selinuxpolicy=$(grep ^SELINUXTYPE /etc/selinux/config |awk -F= '{print $2}')
if [ ! -z "$selinuxpolicy" ]; then
    setfiles /etc/selinux/${selinuxpolicy}/contexts/files/file_contexts /etc/
fi
run_remote_python syncfileclient
run_remote post.custom
# post scripts may be placed into post.d, e.g. post.d/01-firstaction.sh, post.d/02-secondaction.sh
run_remote_parts post.d

# Induce execution of remote configuration, e.g. ansible plays in ansible/post.d/
run_remote_config post.d

curl -sf -X POST -d 'status: staged' -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $confluent_apikey" https://$confluent_websrv/confluent-api/self/updatestatus

kill $logshowpid

