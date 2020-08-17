#!/bin/sh
. /tmp/functions
# This runs whenever this genesis profile boots for customization
# purposes

# run_remote and run_remote_python are available to download scripts and
# execute them.

# This is an example to request the BMC be configured on the network
# according to how confluent has things configured:
# run_remote_python configbmc -c
