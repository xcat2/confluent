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

import confluent.discovery.handlers.redfishbmc as redfishbmc
import eventlet.support.greendns
import confluent.util as util

webclient = eventlet.import_patched('pyghmi.util.webclient')



getaddrinfo = eventlet.support.greendns.getaddrinfo


class NodeHandler(redfishbmc.NodeHandler):
    devname = 'XCC'

    def get_firmware_default_account_info(self):
        return ('USERID', 'PASSW0RD')

    def scan(self):
        ip, port = self.get_web_port_and_ip()
        c = webclient.SecureHTTPConnection(ip, port,
            verifycallback=self.validate_cert)
        i = c.grab_json_response('/api/providers/logoninfo')
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

    def validate_cert(self, certificate):
        fprint = util.get_fingerprint(self.https_cert)
        return util.cert_matches(fprint, certificate)


def remote_nodecfg(nodename, cfm):
    cfg = cfm.get_node_attributes(
            nodename, 'hardwaremanagement.manager')
    ipaddr = cfg.get(nodename, {}).get('hardwaremanagement.manager', {}).get(
        'value', None)
    ipaddr = ipaddr.split('/', 1)[0]
    ipaddr = getaddrinfo(ipaddr, 0)[0][-1]
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

