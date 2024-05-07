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

import codecs
import confluent.discovery.handlers.bmc as bmchandler
import pyghmi.exceptions as pygexc
import pyghmi.ipmi.private.util as pygutil
import confluent.util as util
import struct

class NodeHandler(bmchandler.NodeHandler):
    devname = 'IMM'

    @classmethod
    def adequate(cls, info):
        # We can sometimes receive a partially initialized SLP packet
        # This is not adequate for being satisfied
        return bool(info.get('attributes', {}))

    def scan(self):
        slpattrs = self.info.get('attributes', {})
        self.isdense = False
        try:
            ff = slpattrs.get('enclosure-form-factor', [''])[0]
        except IndexError:
            return
        wronguuid = slpattrs.get('node-uuid', [''])[0]
        if wronguuid:
            # we need to fix the first three portions of the uuid
            uuidprefix = wronguuid.split('-')[:3]
            uuidprefix = codecs.encode(struct.pack(
                '<IHH', *[int(x, 16) for x in uuidprefix]), 'hex')
            uuidprefix = util.stringify(uuidprefix)
            uuidprefix = uuidprefix[:8] + '-' + uuidprefix[8:12] + '-' + \
                         uuidprefix[12:16]
            self.info['uuid'] = uuidprefix + '-' + '-'.join(
                wronguuid.split('-')[3:])
            self.info['uuid'] = self.info['uuid'].lower()
        room = slpattrs.get('room-id', [None])[0]
        if room:
            self.info['room'] = room
        rack = slpattrs.get('rack-id', [None])[0]
        if rack:
            self.info['rack'] = rack
        name = slpattrs.get('name', [None])[0]
        if name:
            self.info['hostname'] = name
        unumber = slpattrs.get('lowest-u', [None])[0]
        if unumber:
            self.info['u'] = unumber
        location = slpattrs.get('location', [None])[0]
        if location:
            self.info['location'] = location
        if ff not in ('dense-computing', 'BC2'):
            # do not probe unless it's a dense platform
            return
        self.isdense = True
        encuuid = slpattrs.get('chassis-uuid', [None])[0]
        if encuuid:
            self.info['enclosure.uuid'] = encuuid
        slot = int(slpattrs.get('slot', ['0'])[0])
        if slot != 0:
            self.info['enclosure.bay'] = slot

    async def probe(self):
        if self.info.get('enclosure.bay', 0) == 0:
            self.scan()
        if self.info.get('enclosure.bay', 0) != 0:
            # scan has already populated info
            return
        ff = self.info.get('attributes', {}).get('enclosure-form-factor', '')
        if ff != 'dense-computing':
            return
        try:
            # we are a dense platform, but the SLP data did not give us slot
            # attempt to probe using IPMI
            ipmicmd = await self._get_ipmicmd()
            guiddata = await ipmicmd.xraw_command(netfn=6, command=8)
            self.info['uuid'] = pygutil.decode_wireformat_uuid(
                guiddata['data']).lower()
            ipmicmd.oem_init()
            bayid = ipmicmd._oem.immhandler.get_property(
                '/v2/cmm/sp/7')
            if not bayid:
                return
            self.info['enclosure.bay'] = int(bayid)
            smmid = ipmicmd._oem.immhandler.get_property(
                '/v2/ibmc/smm/chassis/uuid')
            if not smmid:
                return
            smmid = smmid.lower().replace(' ', '')
            smmid = '{0}-{1}-{2}-{3}-{4}'.format(smmid[:8], smmid[8:12],
                                                 smmid[12:16], smmid[16:20],
                                                 smmid[20:])
            self.info['enclosure.uuid'] = smmid
            self.info['enclosure.type'] = 'smm'
        except pygexc.IpmiException as ie:
            print(repr(ie))
            raise

