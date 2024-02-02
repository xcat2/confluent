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
import confluent.core as core
import confluent.messages as msg
import pyghmi.exceptions as pygexc
import confluent.exceptions as exc
import eventlet
import eventlet.queue as queue
import eventlet.greenpool as greenpool


def reseat_bays(encmgr, bays, configmanager, rspq):
    try:
        for encbay in bays:
            node = bays[encbay]
            try:
                for rsp in core.handle_path(
                        '/nodes/{0}/_enclosure/reseat_bay'.format(encmgr),
                        'update', configmanager,
                        inputdata={'reseat': int(encbay)}):
                    rspq.put(rsp)
            except pygexc.UnsupportedFunctionality as uf:
                rspq.put(msg.ConfluentNodeError(node, str(uf)))
            except exc.TargetEndpointUnreachable as uf:
                rspq.put(msg.ConfluentNodeError(node, str(uf)))
    finally:
        rspq.put(None)

def update(nodes, element, configmanager, inputdata):
    emebs = configmanager.get_node_attributes(
        nodes, (u'enclosure.manager', u'enclosure.bay'))
    baysbyencmgr = {}
    for node in nodes:
        try:
            em = emebs[node]['enclosure.manager']['value']
            eb = emebs[node]['enclosure.bay']['value']
        except KeyError:
            em = node
            eb = -1
        if not em:
            em = node
        if not eb:
            eb = -1
        if em not in baysbyencmgr:
            baysbyencmgr[em] = {}
        baysbyencmgr[em][eb] = node
    rspq = queue.Queue()
    gp = greenpool.GreenPool(64)
    for encmgr in baysbyencmgr:
        gp.spawn_n(reseat_bays, encmgr, baysbyencmgr[encmgr], configmanager, rspq)
    while gp.running():
        nrsp = rspq.get()
        if nrsp is not None:
            yield nrsp
    while not rspq.empty():
        nrsp = rspq.get()
        if nrsp is not None:
            yield nrsp


