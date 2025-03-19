#!/bin/sh
. /etc/confluent/functions
# This runs whenever this genesis profile boots for customization
# purposes

# run_remote and run_remote_python are available to download scripts and
# execute them.

# This will induce server side processing of the syncfile contents if
# present
run_remote_python syncfileclient

run_remote_parts onboot.d


# Induce execution of remote configuration, e.g. ansible plays in ansible/onboot.d/
run_remote_config onboot

# This is an example to request the BMC be configured on the network
# according to how confluent has things configured:
# run_remote_python configbmc -c
