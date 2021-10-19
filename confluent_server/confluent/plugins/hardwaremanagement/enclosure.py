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

def update(nodes, element, configmanager, inputdata):
    emebs = configmanager.get_node_attributes(
        nodes, (u'enclosure.manager', u'enclosure.bay'))
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
        try:
            for rsp in core.handle_path(
                    '/nodes/{0}/_enclosure/reseat_bay'.format(em),
                    'update', configmanager,
                    inputdata={'reseat': int(eb)}):
                yield rsp
        except pygexc.UnsupportedFunctionality as uf:
            yield msg.ConfluentNodeError(node, str(uf))
        except exc.TargetEndpointUnreachable as uf:
            yield msg.ConfluentNodeError(node, str(uf))
