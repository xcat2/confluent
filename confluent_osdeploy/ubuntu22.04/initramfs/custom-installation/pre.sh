#!/bin/bash
deploycfg=/custom-installation/confluent/confluent.deploycfg
confluent_mgr=$(grep ^deploy_server $deploycfg|awk '{print $2}')
confluent_profile=$(grep ^profile: $deploycfg|awk '{print $2}')
curl -f https://$confluent_mgr/confluent-public/os/$confluent_profile/scripts/pre.sh > /tmp/pre.sh
. /tmp/pre.sh
