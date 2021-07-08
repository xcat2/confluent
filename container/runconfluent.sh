#!/bin/bash
rm -f /var/run/confluent/pid /run/confluent/pid >& /dev/null
/opt/confluent/bin/confluent -f
