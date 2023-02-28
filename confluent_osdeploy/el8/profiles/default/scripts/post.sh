#!/bin/sh
mkdir -p /var/log/confluent
chmod 700 /var/log/confluent
exec >> /var/log/confluent/confluent-post.log
exec 2>> /var/log/confluent/confluent-post.log
chmod 600 /var/log/confluent/confluent-post.log
tail -f /var/log/confluent/confluent-post.log > /dev/tty &
logshowpid=$!
nodename=$(grep ^NODENAME /etc/confluent/confluent.info|awk '{print $2}')
apikey=$(cat /etc/confluent/confluent.apikey)

chmod 700 /etc/confluent
chmod og-rwx /etc/confluent/*
export confluent_mgr confluent_profile nodename
. /etc/confluent/functions


if [ -f /tmp/cryptboot ]; then
    run_remote tpm_luks.sh
fi

# By default, the install repository is ignored, change
# this by manually adding local repositories

rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-*
run_remote_python add_local_repositories
# This script will execute in the installed system, but using the installer kernel prior to reboot.
# This is an appropriate place to run post install activities that do not require the actual installed
# kernel to run. For example adding drivers that would be needed for first boot to run cleanly.
# If, for example, there is a post script that has a dependency on a driver or filesystem that
# cannot work until booting into the installer, use firstboot.sh instead

# run_remote will download and execute from /var/lib/confluent/public/os/<profile>/scripts/ directory
# run_remote_python will use the appropriate python interpreter path to run the specified script
# A post.custom is provided to more conveniently hold customizations, see the post.custom file.

# This will induce server side processing of the syncfile contents if
# present
run_remote_python syncfileclient

# run_remote example.sh
# run_remote_python example.py
run_remote post.custom

# Also, scripts may be placed into 'post.d', e.g. post.d/01-runfirst.sh, post.d/02-runsecond.sh
run_remote_parts post.d

# Induce execution of remote configuration, e.g. ansible plays in ansible/post.d/
run_remote_config post.d
cd /root
fetch_remote confignet
cd -
curl -sf -X POST -d 'status: staged' -H "CONFLUENT_NODENAME: $nodename" -H "CONFLUENT_APIKEY: $apikey" https://$confluent_mgr/confluent-api/self/updatestatus
kill $logshowpid
