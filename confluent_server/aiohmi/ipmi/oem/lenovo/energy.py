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

import struct

import aiohmi.constants as const
import aiohmi.exceptions as pygexc
import aiohmi.ipmi.sdr as sdr


class EnergyManager(object):

    @classmethod
    async def create(cls, ipmicmd):
        # there are two IANA possible for the command set, start with
        # the Lenovo, then fallback to IBM
        # We start with a 'find firmware instance' to test the water and
        # get the handle (which has always been the same, but just in case
        self = cls()
        self.iana = bytearray(b'\x66\x4a\x00')
        self._usefapm = False
        self._mypowermeters = ()
        try:
            rsp = await ipmicmd.raw_command(netfn=0x3a, command=0x32, data=[4, 2, 0, 0, 0])
            if len(rsp['data']) >= 8:
                self.supportedmeters = ('DC Energy', 'GPU Power',
                                        'Node Power', 'Total Power')
                self._mypowermeters = ('node power', 'total power', 'gpu power', 'riser 1 power', 'riser 2 power')
                self._usefapm = True
                return self
        except pygexc.IpmiException:
            pass

        try:
            rsp = await ipmicmd.raw_command(netfn=0x2e, command=0x82,
                                       data=self.iana + b'\x00\x00\x01')
        except pygexc.IpmiException as ie:
            if ie.ipmicode == 193:  # try again with IBM IANA
                self.iana = bytearray(b'\x4d\x4f\x00')
                rsp = await ipmicmd.raw_command(netfn=0x2e, command=0x82,
                                           data=self.iana + b'\x00\x00\x01')
            else:
                raise
        if rsp['data'][4:6] not in (b'\x02\x01', b'\x02\x06', b'\x02\x09'):
            raise pygexc.UnsupportedFunctionality(
                "Energy Control {0}.{1} not recognized".format(rsp['data'][4],
                                                               rsp['data'][5]))
        self.modhandle = bytearray(rsp['data'][6:7])
        if await self.get_ac_energy(ipmicmd):
            self.supportedmeters = ('AC Energy', 'DC Energy')
        else:
            self.supportedmeters = ('DC Energy',)
        return self

    def supports(self, name):
        if name.lower() in self._mypowermeters:
            return True
        return False

    async def get_sensor(self, name, ipmicmd):
        if name.lower() not in self._mypowermeters:
            raise pygexc.UnsupportedFunctionality('Unrecogcized sensor')
        tries = 3
        rsp = None
        while tries:
            tries -= 1
            try:
                rsp = await ipmicmd.raw_command(netfn=0x3a, command=0x32, data=[4, 8, 0, 0, 0])
                break
            except pygexc.IpmiException as ie:
                if tries and ie.ipmicode == 0xc3:
                    await ipmicmd.ipmi_session.pause(0.1)
                    continue
                raise
        if rsp is None:
            raise pygexc.UnsupportedFunctionality('Unrecogcized sensor')
        npow, gpupow, r1pow, r2pow = struct.unpack('<HHHH', rsp['data'][6:14])
        if name.lower().startswith('node'):
            return npow, 'W'
        elif name.lower().startswith('gpu'):
            return gpupow, 'W'
        elif name.lower().startswith('total'):
            return npow + gpupow, 'W'

    async def get_fapm_energy(self, ipmicmd):
        rsp = await ipmicmd.raw_command(netfn=0x3a, command=0x32, data=[4, 2, 0, 0, 0])
        j, mj = struct.unpack('<IH', rsp['data'][2:8])
        mj = mj + (j * 1000)
        return float(mj / 1000000 / 3600)

    async def get_energy_precision(self, ipmicmd):
        rsp = await ipmicmd.raw_command(
            netfn=0x2e, command=0x81,
            data=self.iana + self.modhandle + b'\x01\x80')
        print(repr(rsp['data'][:]))

    async def get_ac_energy(self, ipmicmd):
        try:
            rsp = await ipmicmd.raw_command(
                netfn=0x2e, command=0x81,
                data=self.iana + self.modhandle + b'\x01\x82\x01\x08')
            # data is in millijoules, convert to the more recognizable kWh
            return float(
                struct.unpack('!Q', rsp['data'][3:])[0]) / 1000000 / 3600
        except pygexc.IpmiException as ie:
            if ie.ipmicode == 0xcb:
                return 0.0
            raise

    async def get_dc_energy(self, ipmicmd):
        if self._usefapm:
            return await self.get_fapm_energy(ipmicmd)
        rsp = await ipmicmd.raw_command(
            netfn=0x2e, command=0x81,
            data=self.iana + self.modhandle + b'\x01\x82\x00\x08')
        # data is in millijoules, convert to the more recognizable kWh
        return float(struct.unpack('!Q', rsp['data'][3:])[0]) / 1000000 / 3600


class Energy(object):

    def __init__(self, ipmicmd):
        self.ipmicmd = ipmicmd

    async def get_energy_sensor(self):
        # read the cpu usage

        try:
            rsp = await self.ipmicmd.raw_command(netfn=0x04,
                                            command=0x2d,
                                            bridge_request={"addr": 0x2c,
                                                            "channel": 0x06},
                                            data=[0xbe])
        except pygexc.IpmiException:
            return
        rdata = bytearray(rsp["data"])
        cpu_usage = rdata[0] * 100 / 0xff
        # mimic the power sensor
        temp = {'name': "CPU_Usage",
                'health': const.Health.Ok,
                'states': [],
                'state_ids': [],
                'type': "Processor",
                'units': "%",
                'value': cpu_usage,
                'imprecision': None}
        yield (sdr.SensorReading(temp, temp['units']))


if __name__ == '__main__':
    import asyncio
    import os
    import aiohmi.ipmi.command as cmd
    import sys

    async def main():
        c = await cmd.Command.create(sys.argv[1], os.environ['BMCUSER'], os.environ['BMCPASS'])
        manager = await EnergyManager.create(c)
        print(await manager.get_dc_energy(c))

    asyncio.run(main())
