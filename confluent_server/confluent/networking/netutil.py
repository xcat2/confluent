# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2017 Lenovo
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
import confluent.util as util
import confluent.noderange as noderange
import confluent.collective.manager as collective


def get_switchcreds(configmanager, switches):
    switchcfg = configmanager.get_node_attributes(
        switches, ('secret.hardwaremanagementuser', 'secret.snmpcommunity',
                   'secret.hardwaremanagementpassword',
                   'collective.managercandidates'), decrypt=True)
    switchauth = []
    for switch in switches:
        if not switch:
            continue
        candmgrs = switchcfg.get(switch, {}).get('collective.managercandidates', {}).get('value', None)
        if candmgrs:
            candmgrs = noderange.NodeRange(candmgrs, configmanager).nodes
            if collective.get_myname() not in candmgrs:
                continue
        switchparms = switchcfg.get(switch, {})
        user = None
        password = switchparms.get(
            'secret.snmpcommunity', {}).get('value', None)
        if not password:
            password = switchparms.get(
                'secret.hardwaremanagementpassword', {}).get('value',
                                                             'public')
            user = switchparms.get(
                'secret.hardwaremanagementuser', {}).get('value', None)
            if not user:
                user = None
        switchauth.append((switch, password, user, configmanager))
    return switchauth


def list_switches(configmanager):
    nodelocations = configmanager.get_node_attributes(
        configmanager.list_nodes(), ('type', 'net*.switch', 'net*.switchport'))
    switches = set([])
    for node in nodelocations:
        cfg = nodelocations[node]
        if cfg.get('type', {}).get('value', None) == 'switch':
            switches.add(node)
        for attr in cfg:
            if not attr.endswith('.switch') or 'value' not in cfg[attr]:
                continue
            curswitch = cfg[attr].get('value', None)
            if not curswitch:
                continue
            switches.add(curswitch)
    return util.natural_sort(switches)


async def get_portnamemap(conn):
    ifnamemap = {}
    havenames = False
    async for vb in conn.walk('1.3.6.1.2.1.31.1.1.1.1'):
        ifidx, ifname = vb
        if not ifname:
            continue
        havenames = True
        ifidx = int(str(ifidx).rsplit('.', 1)[1])
        ifnamemap[ifidx] = str(ifname)
    if not havenames:
        async for vb in conn.walk('1.3.6.1.2.1.2.2.1.2'):
            ifidx, ifname = vb
            ifidx = int(str(ifidx).rsplit('.', 1)[1])
            ifnamemap[ifidx] = str(ifname)
    return ifnamemap
