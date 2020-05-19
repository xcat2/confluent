#!/bin/bash
deploycfg=/custom-installation/confluent/confluent.deploycfg
mgr=$(grep ^deploy_server $deploycfg|awk '{print $2}')
profile=$(grep ^profile: $deploycfg|awk '{print $2}')
curl -f https://$mgr/confluent-public/os/$profile/scripts/pre.sh > /tmp/pre.sh
. /tmp/pre.sh
