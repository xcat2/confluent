# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2015 Lenovo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This handles incoming unsolicited alerts over the network.  For the moment
# we'll link into ipmi.py to do PET alerts, with the assumption that more
# typical .mib based handling will be used for other events and confluent's
# event service is to handle the peculiarities of an IPMI PET.  In the future
# it may make sense to extend this in a more general case, but that rework can
# be deferred for now.

# Phase 1 is to be facilitating some application doing http calls to get help
# decoding data.

# Phase 2 is to be able to bind a port and have snmptrapd just forward the
# packet rather than have something block snmptrapd at all for things confluent
# can handle.

__author__ = 'jjohnson2'

import confluentd.exceptions as exc
import confluentd.lookuptools as lookuptools
import confluentd.core

def decode_alert(varbinds, configmanager):
    """Decode an SNMP alert for a server

    Given the agentaddr, OID for the trap, and a dict of varbinds,
    ascertain the node identity and then request a decode

    :param varbinds: A dictionary of OID to value varbinds.  Also supported
                     are special keywords 'enterprise' and 'specificTrap' for
                    SNMPv1 traps.

    """
    try:
        agentaddr = varbinds['.1.3.6.1.6.3.18.1.3.0']
    except KeyError:
        agentaddr = varbinds['1.3.6.1.6.3.18.1.3.0']
    node = lookuptools.node_by_manager(agentaddr)
    if node is None:
        raise exc.InvalidArgumentException(
            'Unable to find a node with specified manager')
    return confluentd.core.handle_path(
        '/nodes/{0}/events/hardware/decode'.format(node), 'update',
        configmanager, varbinds, autostrip=False)

