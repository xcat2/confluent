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
import confluent.tasks as tasks
import asyncio
import confluent.core as core
import confluent.messages as msg
import confluent.exceptions as exc

class TaskDone:
    pass

async def retrieve(nodes, element, configmanager, inputdata):
    emebs = configmanager.get_node_attributes(
        nodes, (u'power.*pdu', u'power.*outlet'))
    relpdus = {}
    if element == ['power', 'inlets']:
        outletnames = set([])
        for node in nodes:
            for attrib in emebs[node]:
                attrib = attrib.replace('power.', '').rsplit('.', 1)
                if len(attrib) > 1:
                    outletnames.add('inlet_' + attrib[0])
                else:
                    outletnames.add('default')
        if outletnames:
            outletnames.add('all')
        for inlet in outletnames:
            yield msg.ChildCollection(inlet)
    elif len(element) == 3:
        inletname = element[-1]
        outlets = get_outlets(nodes, emebs, inletname)
        for node in outlets:
            if not outlets[node]:
                yield msg.ConfluentTargetNotFound(node, 'No matching inlets defined for node in "power.*" attributes')
            for pgroup in outlets[node]:
                pdu = outlets[node][pgroup]['pdu']
                outlet = outlets[node][pgroup]['outlet']
                if pdu not in relpdus:
                    relpdus[pdu] = {}
                relpdus[pdu][outlet] = (node, pgroup)
        rspq = asyncio.Queue()
        gp = tasks.TaskPool(64)
        for pdu in relpdus:
            gp.schedule(readpdu, pdu, relpdus[pdu], configmanager, rspq)
        while gp.running():
            try:
                nrsp = await asyncio.wait_for(rspq.get(), timeout=0.1)
                if nrsp is not None and not isinstance(nrsp, TaskDone):
                    yield nrsp

            except asyncio.TimeoutError:
                continue
        while not rspq.empty():
            nrsp = await rspq.get()
            if not isinstance(nrsp, TaskDone):
                yield nrsp

async def readpdu(pdu, outletmap, configmanager, rspq):
    try:
        for outlet in outletmap:
            node, pgroup = outletmap[outlet]
            try:
                responses = await core.handle_path(
                        '/nodes/{0}/power/outlets/{1}'.format(pdu, outlet),
                        'retrieve', configmanager)
                async for rsp in core.iterate_responses(responses):
                    await rspq.put(msg.KeyValueData({pgroup: rsp.kvpairs['state']['value']}, node))
            except exc.TargetEndpointBadCredentials:
                    await rspq.put(msg.ConfluentTargetInvalidCredentials(pdu))
    finally:  # ensure that at least one thing triggers the get
        await rspq.put(TaskDone())


def get_outlets(nodes, emebs, inletname):
    outlets = {}
    for node in nodes:
        if node not in outlets:
            outlets[node] = {}
        for attrib in emebs[node]:
            v = emebs[node][attrib].get('value', None)
            if not v:
                continue
            attrib = attrib.replace('power.', '').rsplit('.', 1)
            if len(attrib) > 1:
                pgroup = 'inlet_' + attrib[0]
            else:
                pgroup = 'default'
            if inletname == 'all' or pgroup == inletname:
                if pgroup not in outlets[node]:
                    outlets[node][pgroup] = {}
                outlets[node][pgroup][attrib[-1]] = v
    return outlets


async def update(nodes, element, configmanager, inputdata):
    emebs = configmanager.get_node_attributes(
        nodes, (u'power.*pdu', u'power.*outlet'))
    inletname = element[-1]
    relpdus = {}
    rspq = asyncio.Queue()
    gp = tasks.TaskPool(64)
    outlets = get_outlets(nodes, emebs, inletname)
    for node in outlets:
        if not outlets[node]:
                yield msg.ConfluentTargetNotFound(node, 'No matching inlets defined for node in "power.*" attributes')
        for pgroup in outlets[node]:
            pdu = outlets[node][pgroup]['pdu']
            outlet = outlets[node][pgroup]['outlet']
            if pdu not in relpdus:
                relpdus[pdu] = {}
            relpdus[pdu][outlet] = (node, pgroup)
    for pdu in relpdus:
        gp.schedule(updatepdu, pdu, relpdus[pdu], configmanager, inputdata, rspq)
    while gp.running():
        try:
            nrsp = await asyncio.wait_for(rspq.get(), timeout=0.1)
            if nrsp is not None and not isinstance(nrsp, TaskDone):
                yield nrsp
        except asyncio.TimeoutError:
            continue
    while not rspq.empty():
        nrsp = await rspq.get()
        if not isinstance(nrsp, TaskDone):
            yield nrsp

async def updatepdu(pdu, outletmap, configmanager, inputdata, rspq):
    try:
        for outlet in outletmap:
            node, pgroup = outletmap[outlet]
            responses = await core.handle_path('/nodes/{0}/power/outlets/{1}'.format(pdu, outlet),
                                               'update', configmanager, inputdata={'state': inputdata.powerstate(node)})
            async for rsp in core.iterate_responses(responses):
                await rspq.put(msg.KeyValueData({pgroup: rsp.kvpairs['state']['value']}, node))
    finally:
        await rspq.put(TaskDone())
