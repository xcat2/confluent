#!/bin/bash
serialcons=$(tty)
if [ -e /run/confluent/01-autocons.conf ]; then
    serialcons=$(cat /run/confluent/01-autocons.conf|sed -e s/.*=// -e s/,.*//)
    if [ -n "$serialcons" ]; then
        serialcons=/dev/$serialcons
    else
        serialcons=$(tty)
    fi
fi
profile=$(grep ^profile: /etc/confluent/confluent.deploycfg|awk '{print $2}')
export profile
python3 /opt/confluent/bin/apiclient /confluent-public/os/$profile/scripts/functions > /etc/confluent/functions
. /etc/confluent/functions
touch /tmp/confluent-pre.log
tail -f /tmp/confluent-pre.log > $serialcons 2>&1 &
tailpid=$!
python3 /opt/confluent/bin/apiclient /confluent-public/os/$profile/scripts/pre.sh > /tmp/pre.sh 2> $serialcons
chmod +x /tmp/pre.sh
/tmp/pre.sh > $serialcons 2>&1
kill $tailpid
agama config load /tmp/autoinstall.json > $serialcons 2>&1
agama install > $serialcons 2>&1
python3 /opt/confluent/bin/apiclient /confluent-public/os/$profile/scripts/post.sh > /tmp/post.sh 2> $serialcons
chmod +x /tmp/post.sh
touch /tmp/confluent-post.log
tail -f /tmp/confluent-post.log > $serialcons 2>&1 &
/tmp/post.sh > $serialcons 2>&1
agama finish > $serialcons 2>&1
