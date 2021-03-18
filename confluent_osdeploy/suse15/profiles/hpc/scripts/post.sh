#!/bin/sh

# This script runs at the end of install in the installed system
# but still under the installer kernel.

# This is a good place to run most customizations that do not have any
# dependency upon the install target kernel being active.

# If there are dependencies on the kernel (drivers or special filesystems)
# then firstboot.sh would be the script to customize.

mgr=$(grep ^deploy_server /etc/confluent/confluent.deploycfg|awk '{print $2}')
profile=$(grep ^profile: /etc/confluent/confluent.deploycfg|sed -e 's/^profile: //')
nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
apikey=$(cat /etc/confluent/confluent.apikey)

chmod 700 /etc/confluent
chmod og-rwx /etc/confluent/*


export mgr profile nodename
. /etc/confluent/functions

run_remote post.custom

# Also, scripts may be placed into 'post.d', e.g. post.d/01-runfirst.sh, post.d/02-runsecond.sh
run_remote_parts post

# Induce execution of remote configuration, e.g. ansible plays in ansible/post.d/
run_remote_config post

curl -X POST -d 'status: staged' -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $apikey" https://$mgr/confluent-api/self/updatestatus

