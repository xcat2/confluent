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

# Utility library for interesting lookups of nodes.
# Examples:
#     looking up a node by a hardwaremanagement.manager address
#     looking up a node by uuid (actually pretty straightforward
#     looking up a node by mac address
# These are generally in the context of coming in from some unstructured
# direction (alerts, PXE attempt) and for now will only look at the null
# tenant (all baremetal tenants that are expected to receive alert/pxe
# service should have a null tenant and a tenant entry that correlates)
__author__ = 'jjohnson2'

import confluent.config.configmanager as configmanager
import itertools
from eventlet.support import greendns

manager_to_nodemap = {}

def node_by_manager(manager):
    """Lookup a node by manager

    Search for a node according to a given network address.
    Rather than do a simple equality, it uses getaddrinfo
    to allow name or ip and different forms of ip.  For
    example, 'fe80::0001' will match 'fe80::01' and
    '127.000.000.001' will match '127.0.0.1'

    :param manager: The ip or resolvable name of the manager

    :returns: The node name (if any)
    """

    manageraddresses = []
    for tmpaddr in greendns.getaddrinfo(manager, None):
        manageraddresses.append(tmpaddr[4][0])
    cfm = configmanager.ConfigManager(None)
    if manager in manager_to_nodemap:
        # We have a stored hint as to the most probably correct answer
        # put that node at the head of the list in hopes of reducing
        # iterations for a lookup in a large environment
        # However we don't trust the answer either, since
        # reconfiguration could have changed it and this mapping
        # is not hooked into getting updates
        check_nodes = itertools.chain(
            (manager_to_nodemap[manager],), cfm.list_nodes())
    else:
        check_nodes = cfm.list_nodes()
    hmattribs = cfm.get_node_attributes(check_nodes,
                                        ('hardwaremanagement.manager',))
    for node in hmattribs:
        currhm = hmattribs[node]['hardwaremanagement.manager']['value']
        currhm = currhm.split('/', 1)[0]
        if currhm in manageraddresses:
            manager_to_nodemap[manager] = node
            return node
        for curraddr in greendns.getaddrinfo(currhm, None):
            curraddr = curraddr[4][0]
            if curraddr in manageraddresses:
                manager_to_nodemap[manager] = node
                return node