# Copyright 2023 Lenovo
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

import confluent.core as core
import confluent.messages as msg

def baytonumber(bay):
    if not bay:
        return None
    try:
        return int(bay)
    except ValueError:
        if len(bay) == 2:
            # Treat a hexadecimal system as a leading decimal digit and letter compile
            # 1a == slot 1, 1b == slot 2, 2a == slot 1, etc..
            try:
                tmp = int(bay, 16)
                return (2 * (tmp >> 4) - 1) + ((tmp & 15) % 10)
            except ValueError:
                return None
    return None

def retrieve(nodes, element, configmanager, inputdata):
    locationinfo = configmanager.get_node_attributes(nodes,
            (u'enclosure.manager', u'enclosure.bay', u'location.rack',
             u'location.row', u'location.u', u'location.height'))
    enclosuremap = {}
    rackmap = {}
    allnodedata = {}
    needenclosures = set([])
    locatednodes = set([])
    needcoord = {}
    for node in locationinfo:
        nodeinfo = locationinfo[node]
        rack = nodeinfo.get(u'location.rack', {}).get('value', '')
        u = nodeinfo.get(u'location.u', {}).get('value', None)
        row = nodeinfo.get(u'location.row', {}).get('value', '')
        enclosure = nodeinfo.get(u'enclosure.manager', {}).get('value', None)
        bay = nodeinfo.get(u'enclosure.bay', {}).get('value', None)

        height = nodeinfo.get(u'location.height', {}).get('value', None)
        if enclosure:
            if enclosure not in enclosuremap:
                enclosuremap[enclosure] = {'bays': {}, 'coordinates': {}}
            bay = baytonumber(bay)
            if bay is None:
                continue
            bay = f'{bay}'
            enclosuremap[enclosure]['bays'][bay] = node
            needcoord[node] = enclosure
            if u:
                if row not in rackmap:
                    rackmap[row] = {}
                if rack not in rackmap[row]:
                    rackmap[row][rack] = {}
                rackmap[row][rack][u] = {'node': enclosure, 'children': enclosuremap[enclosure]['bays'], 'nodecoordinates': enclosuremap[enclosure]['coordinates']}
                allnodedata[enclosure] = rackmap[row][rack][u]
                if height:
                    allnodedata[enclosure]['height'] = int(height)
            else: # need to see if enclosure lands in the map naturally or need to pull it
                needenclosures.add(enclosure)
        elif u:
            if row not in rackmap:
                rackmap[row] = {}
            if rack not in rackmap[row]:
                rackmap[row][rack] = {}
            rackmap[row][rack][u] = {'node': node}
            allnodedata[node] = rackmap[row][rack][u]
            if height:
                allnodedata[node]['height'] = int(height)
            locatednodes.add(node)
    cfgenc = needenclosures - locatednodes
    locationinfo = configmanager.get_node_attributes(cfgenc, (u'location.rack', u'location.row', u'location.u', u'location.height'))
    for enclosure in locationinfo:
        nodeinfo = locationinfo[enclosure]
        rack = nodeinfo.get(u'location.rack', {}).get('value', '')
        u = nodeinfo.get(u'location.u', {}).get('value', None)
        row = nodeinfo.get(u'location.row', {}).get('value', '')
        height = nodeinfo.get(u'location.height', {}).get('value', None)
        if u:
            allnodedata[enclosure] = {'node': enclosure, 'children': enclosuremap[enclosure]['bays'], 'nodecoordinates': enclosuremap[enclosure]['coordinates']}
            if height:
                allnodedata[enclosure]['height'] = int(height)
            if row not in rackmap:
                rackmap[row] = {}
            if rack not in rackmap[row]:
                rackmap[row][rack] = {}
            rackmap[row][rack][u] = allnodedata[enclosure]
    results = {
        'errors': [],
        'locations': rackmap,
    }
    for enclosure in enclosuremap:
        if enclosure not in allnodedata:
            results['errors'].append('Enclosure {} is missing required location information'.format(enclosure))
        else:
            allnodedata[enclosure]['children'] = enclosuremap[enclosure]['bays']
            allnodedata[enclosure]['nodecoordinates'] = enclosuremap[enclosure]['coordinates']
    needheight = set([])
    needslots = set(enclosuremap)
    for node in allnodedata:
        if 'height' not in allnodedata[node]:
            needheight.add(node)
    needheightrange = ','.join(needheight.union(needslots).union(needcoord))
    if needheightrange:
        for rsp in core.handle_path(
            '/noderange/{0}/description'.format(needheightrange),
            'retrieve', configmanager,
            inputdata=None):
                if not hasattr(rsp, 'kvpairs'):
                    results['errors'].append((rsp.node, rsp.error))
                    continue
                kvp = rsp.kvpairs
                for node in kvp:
                    if node in needheight:
                        allnodedata[node]['height'] = kvp[node]['height']
                    if node in needslots and 'slots' in kvp[node]:
                        allnodedata[node]['slots'] = kvp[node]['slots']
                    if node in needcoord and 'slotcoord' in kvp[node]:
                        enclosuremap[needcoord[node]]['coordinates'][node] = kvp[node]['slotcoord']
                        del needcoord[node]
    for enclosure in enclosuremap:
        if 'slots' not in allnodedata[enclosure]:
            # if slots not described by chassis, assume a double-wide form factor
            allnodedata[enclosure]['slots'] = [2, allnodedata[enclosure]['height']]
    for node in needcoord:  # have to fill in based on heuristic absent of specific data
        enclosure = needcoord[node]
        currslot = None
        for bay in enclosuremap[enclosure]['bays']:
            if enclosuremap[enclosure]['bays'][bay] == node:
                currslot = int(bay)
        if currslot is None:
            continue
        if enclosure in allnodedata and 'slots' in allnodedata[enclosure]:
            dimensions = allnodedata[enclosure]['slots']
            if dimensions[0] > dimensions[1]:
                enclosuremap[enclosure]['coordinates'][node] = [(currslot - 1) // dimensions[1] + 1, (currslot - 1) % dimensions[1] + 1]
            else:
                enclosuremap[enclosure]['coordinates'][node] = [(currslot - 1) % dimensions[0] + 1, (currslot - 1) // dimensions[0] + 1]
    for node in allnodedata:
        if 'height' not in allnodedata[node]:
            allnodedata[node]['height'] = 1
    yield msg.Generic(results)

