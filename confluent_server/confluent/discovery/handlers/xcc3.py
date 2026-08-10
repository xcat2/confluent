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

import codecs
import confluent.discovery.handlers.redfishbmc as redfishbmc
import confluent.util as util
import socket
import struct
import aiohmi.util.webclient as webclient


# Duplicated from the xcc handler rather than imported: xcc imports this
# module, so importing it back would be circular.  smm carries its own copy of
# this for the same reason.
def fixuuid(baduuid):
    # SMM dumps it out in hex
    uuidprefix = (baduuid[:8], baduuid[9:13], baduuid[14:18])
    a = codecs.encode(struct.pack('<IHH', *[int(x, 16) for x in uuidprefix]),
        'hex')
    a = util.stringify(a)
    uuid = (a[:8], a[8:12], a[12:16], baduuid[19:23], baduuid[24:])
    return '-'.join(uuid).lower()


class NodeHandler(redfishbmc.NodeHandler):
    devname = 'XCC'

    def get_firmware_default_account_info(self):
        return ('USERID', 'PASSW0RD')

    async def get_manager_url(self, wc):
        return '/redfish/v1/Managers/1'

    async def scan(self):
        ip, port = await self.get_web_port_and_ip()
        await self.get_https_cert()
        c = webclient.WebConnection(ip, port,
            verifycallback=self.validate_cert)
        c.set_header('Accept', 'application/json')
        i = await c.grab_json_response('/api/providers/logoninfo')
        modelname = i.get('items', [{}])[0].get('machine_name', None)
        if modelname:
            self.info['modelname'] = modelname
        for attrname in list(self.info.get('attributes', {})):
            val = self.info['attributes'][attrname]
            if '-uuid' == attrname[-5:] and len(val) == 32:
                val = val.lower()
                self.info['attributes'][attrname] = '-'.join([val[:8], val[8:12], val[12:16], val[16:20], val[20:]])
        attrs = self.info.get('attributes', {})
        room = attrs.get('room-id', None)
        if room:
            self.info['room'] = room
        rack = attrs.get('rack-id', None)
        if rack:
            self.info['rack'] = rack
        name = attrs.get('name', None)
        if name:
            self.info['hostname'] = name
        unumber = attrs.get('lowest-u', None)
        if unumber:
            self.info['u'] = unumber
        location = attrs.get('location', None)
        if location:
            self.info['location'] = location
        mtm = attrs.get('enclosure-machinetype-model', None)
        if mtm:
            self.info['modelnumber'] = mtm.strip()
        sn = attrs.get('enclosure-serial-number', None)
        if sn:
            self.info['serialnumber'] = sn.strip()
        if attrs.get('enclosure-form-factor', None) == 'dense-computing':
            encuuid = attrs.get('chassis-uuid', None)
            if encuuid:
                self.info['enclosure.uuid'] = fixuuid(encuuid)
            slot = int(attrs.get('slot', 0))
            if slot != 0:
                self.info['enclosure.bay'] = slot




def remote_nodecfg(nodename, cfm):
    cfg = cfm.get_node_attributes(
            nodename, 'hardwaremanagement.manager')
    ipaddr = cfg.get(nodename, {}).get('hardwaremanagement.manager', {}).get(
        'value', None)
    ipaddr = ipaddr.split('/', 1)[0]
    ipaddr = socket.getaddrinfo(ipaddr, 0)[0][-1]
    if not ipaddr:
        raise Exception('Cannot remote configure a system without known '
                        'address')
    info = {'addresses': [ipaddr]}
    nh = NodeHandler(info, cfm)
    nh.config(nodename)


if __name__ == '__main__':
    import confluent.config.configmanager as cfm
    c = cfm.ConfigManager(None)
    import sys
    info = {'addresses': [[sys.argv[1]]]}
    print(repr(info))
    testr = NodeHandler(info, c)
    testr.config(sys.argv[2])

