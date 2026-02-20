# Copyright 2024 Lenovo
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

import asyncio

import confluent.discovery.handlers.redfishbmc as redfishbmc

class NodeHandler(redfishbmc.NodeHandler):

    def get_firmware_default_account_info(self):
        return ('admin', 'admin')


async def remote_nodecfg(nodename, cfm):
    cfg = cfm.get_node_attributes(
            nodename, 'hardwaremanagement.manager')
    ipaddr = cfg.get(nodename, {}).get('hardwaremanagement.manager', {}).get(
        'value', None)
    ipaddr = ipaddr.split('/', 1)[0]
    ipaddr = (await asyncio.get_event_loop().getaddrinfo(ipaddr, 0))[0][-1]
    if not ipaddr:
        raise Exception('Cannot remote configure a system without known '
                        'address')
    info = {'addresses': [ipaddr]}
    nh = NodeHandler(info, cfm)
    await nh.config(nodename)


if __name__ == '__main__':
    import confluent.config.configmanager as cfm
    c = cfm.ConfigManager(None)
    import sys
    info = {'addresses': [[sys.argv[1]]]}
    print(repr(info))
    testr = NodeHandler(info, c)
    testr.config(sys.argv[2])

