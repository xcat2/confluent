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

def retrieve(nodes, element, configmanager, inputdata):
    locationinfo = configmanager.get_node_attributes(nodes,
            (u'enclosure.manager', u'enclosure.bay', u'location.rack',
             u'location.row', u'location.u', u'location.height'))
    enclosuremap = {}
    rackmap = {}
    allnodedata = {}
    needenclosures = set([])
    locatednodes = set([])
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
                enclosuremap[enclosure] = {}
            enclosuremap[enclosure][bay] = node
            if u:
                if row not in rackmap:
                    rackmap[row] = {}
                if rack not in rackmap[row]:
                    rackmap[row][rack] = {}
                rackmap[row][rack][u] = {'node': enclosure, 'children': enclosuremap[enclosure]}
                allnodedata[enclosure] = rackmap[row][rack][u]
                if height:
                    allnodedata[enclosure]['height'] = height
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
                allnodedata[node]['height'] = height
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
            allnodedata[enclosure] = {'node': enclosure, 'children': enclosuremap[enclosure]}
            if height:
                allnodedata[enclosure]['height'] = height
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
            allnodedata[enclosure]['children'] = enclosuremap[enclosure]
    needheight = set([])
    for node in allnodedata:
        if 'height' not in allnodedata[node]:
            needheight.add(node)
    needheight = ','.join(needheight)
    if needheight:
        for rsp in core.handle_path(
            '/noderange/{0}/description'.format(needheight),
            'retrieve', configmanager,
            inputdata=None):
                if not hasattr(rsp, 'kvpairs'):
                    results['errors'].append((rsp.node, rsp.error))
                    continue
                kvp = rsp.kvpairs
                for node in kvp:
                    allnodedata[node]['height'] = kvp[node]['height']
    yield msg.Generic(results)

