# Copyright 2015-2017 Lenovo
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

import base64
import binascii
import socket
import struct
import traceback
import weakref

import aiohmi.constants as pygconst
import aiohmi.exceptions as pygexc
import aiohmi.ipmi.oem.generic as generic
from aiohmi.ipmi.oem.lenovo import cpu
from aiohmi.ipmi.oem.lenovo import dimm
from aiohmi.ipmi.oem.lenovo import drive
from aiohmi.ipmi.oem.lenovo import energy
from aiohmi.ipmi.oem.lenovo import firmware
from aiohmi.ipmi.oem.lenovo import imm
from aiohmi.ipmi.oem.lenovo import inventory
from aiohmi.ipmi.oem.lenovo import nextscale
from aiohmi.ipmi.oem.lenovo import pci
from aiohmi.ipmi.oem.lenovo import psu
from aiohmi.ipmi.oem.lenovo import raid_controller
from aiohmi.ipmi.oem.lenovo import raid_drive
import aiohmi.ipmi.private.constants as ipmiconst
import aiohmi.ipmi.private.util as util
import aiohmi.redfish.command as redfishcmd
from aiohmi.redfish.oem.lenovo import tsma
import aiohmi.util.webclient as wc

try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode

try:
    range = xrange
except NameError:
    pass
try:
    buffer
except NameError:
    buffer = memoryview

inventory.register_inventory_category(cpu)
inventory.register_inventory_category(dimm)
inventory.register_inventory_category(pci)
inventory.register_inventory_category(drive)
inventory.register_inventory_category(psu)
inventory.register_inventory_category(raid_drive)
inventory.register_inventory_category(raid_controller)


firmware_types = {
    1: 'Management Controller',
    2: 'UEFI/BIOS',
    3: 'CPLD',
    4: 'Power Supply',
    5: 'Storage Adapter',
    6: 'Add-in Adapter',
}

firmware_event = {
    0: ('Update failed', pygconst.Health.Failed),
    1: ('Update succeeded', pygconst.Health.Ok),
    2: ('Update aborted', pygconst.Health.Ok),
    3: ('Unknown', pygconst.Health.Warning),
}

me_status = {
    0: ('Recovery GPIO forced', pygconst.Health.Warning),
    1: ('ME Image corrupt', pygconst.Health.Critical),
    2: ('Flash erase error', pygconst.Health.Critical),
    3: ('Unspecified flash state', pygconst.Health.Warning),
    4: ('ME watchdog timeout', pygconst.Health.Critical),
    5: ('ME platform reboot', pygconst.Health.Critical),
    6: ('ME update', pygconst.Health.Ok),
    7: ('Manufacturing error', pygconst.Health.Critical),
    8: ('ME Flash storage integrity error', pygconst.Health.Critical),
    9: ('ME firmware exception', pygconst.Health.Critical),  # event data 3..
    0xa: ('ME firmware worn', pygconst.Health.Warning),
    0xc: ('Invalid SCMP state', pygconst.Health.Warning),
    0xd: ('PECI over DMI failure', pygconst.Health.Warning),
    0xe: ('MCTP interface failure', pygconst.Health.Warning),
    0xf: ('Auto configuration completed', pygconst.Health.Ok),
}

me_flash_status = {
    0: ('ME flash corrupted', pygconst.Health.Critical),
    1: ('ME flash erase limit reached', pygconst.Health.Critical),
    2: ('ME flash write limit reached', pygconst.Health.Critical),
    3: ('ME flash write enabled', pygconst.Health.Ok),
}

leds = {
    "BMC_UID": 0x00,
    "BMC_HEARTBEAT": 0x01,
    "SYSTEM_FAULT": 0x02,
    "PSU1_FAULT": 0x03,
    "PSU2_FAULT": 0x04,
    "LED_FAN_FAULT_1": 0x10,
    "LED_FAN_FAULT_2": 0x11,
    "LED_FAN_FAULT_3": 0x12,
    "LED_FAN_FAULT_4": 0x13,
    "LED_FAN_FAULT_5": 0x14,
    "LED_FAN_FAULT_6": 0x15,
    "LED_FAN_FAULT_7": 0x16,
    "LED_FAN_FAULT_8": 0x17
}

led_status = {
    0x00: "Off",
    0xFF: "On"
}

ami_leds = {
    "BMC_HEARTBEAT": 0x00,
    "BMC_UID": 0x01,
    "SYSTEM_FAULT": 0x02,
    "HDD_FAULT": 0x03
}

asrock_leds = {
    "SYSTEM_EVENT": 0x00,
    "BMC_UID": 0x01,
    "LED_FAN_FAULT_1": 0x02,
    "LED_FAN_FAULT_2": 0x03,
    "LED_FAN_FAULT_3": 0x04
}

ts460_leds = {
    "SYSTEM_EVENT": 0x00,
    "BMC_UID": 0x01,
    "LED_FAN_FAULT_1": 0x02,
    "LED_FAN_FAULT_2": 0x03,
    "LED_FAN_CPU": 0x04,
    "LED_FAN_REAR": 0x05
}

asrock_led_status = {
    0x00: "Off",
    0x01: "On"
}

ami_led_status = {
    0x00: "Off",
    0x01: "On"
}

led_status_default = "Blink"
mac_format = '{0:02x}:{1:02x}:{2:02x}:{3:02x}:{4:02x}:{5:02x}'
categorie_items = ["cpu", "dimm", "firmware", "bios_version"]


def _megarac_abbrev_image(name):
    # MegaRAC platform in some places needs an abbreviated filename
    # Their scheme in such a scenario is a max of 20.  Truncation is
    # acheived by taking the first sixteen, then skipping ahead to the last
    # 4 (presumably to try to keep '.iso' or '.img' in the name).
    if len(name) <= 20:
        return name
    return name[:16] + name[-4:]


class OEMHandler(generic.OEMHandler):
    # noinspection PyUnusedLocal
    @classmethod
    async def create(cls, oemid, ipmicmd):
        self = cls()
        # will need to retain data to differentiate
        # variations.  For example System X versus Thinkserver
        self.oemid = oemid
        self._fpc_variant = None
        self.ipmicmd = weakref.proxy(ipmicmd)
        self._has_megarac = None
        self.oem_inventory_info = None
        self._mrethidx = None
        self._hasimm = None
        self._hasxcc = None
        if await self.has_xcc():
            self.immhandler = imm.XCCClient(ipmicmd)
        elif await self.has_imm():
            self.immhandler = imm.IMMClient(ipmicmd)
        elif await self.is_fpc():
            self.smmhandler = nextscale.SMMClient(ipmicmd, await self.is_fpc())
        elif self.has_tsma:
            conn = wc.WebConnection(
                ipmicmd.bmc, 443,
                verifycallback=self.ipmicmd.certverify)
            self.tsmahandler = await tsma.TsmHandler.create(None, None, conn,
                                                            fish=redfishcmd)
            self.tsmahandler.set_credentials(
                ipmicmd.ipmi_session.userid.decode('utf-8'),
                ipmicmd.ipmi_session.password.decode('utf-8'))
        return self

    
    async def _megarac_eth_index(self):
        if self._mrethidx is None:
            chan = await self.ipmicmd.get_network_channel()
            rsp = await self.ipmicmd.raw_command(0x32, command=0x62, data=(chan,))
            self._mrethidx = rsp['data'][0]
        return self._mrethidx
 
    async def get_screenshot(self, outfile):
        if await self.has_xcc():
            return await self.immhandler.get_screenshot(outfile)
        return {}

    async def remove_storage_configuration(self, cfgspec):
        if await self.has_xcc():
            return await self.immhandler.remove_storage_configuration(cfgspec)
        return await super(OEMHandler, self).remove_storage_configuration()

    async def get_ikvm_methods(self):
        if await self.has_xcc():
            return ['url']

    async def get_ikvm_launchdata(self):
        if await self.has_xcc():
            return await self.immhandler.get_ikvm_launchdata()
        return {}

    async def clear_storage_arrays(self):
        if await self.has_xcc():
            return await self.immhandler.clear_storage_arrays()
        return await super(OEMHandler, self).clear_storage_arrays()

    async def apply_storage_configuration(self, cfgspec):
        if await self.has_xcc():
            return await self.immhandler.apply_storage_configuration(cfgspec)
        return await super(OEMHandler, self).apply_storage_configuration()

    async def check_storage_configuration(self, cfgspec):
        if await self.has_xcc():
            return await self.immhandler.check_storage_configuration(cfgspec)
        return await super(OEMHandler, self).get_storage_configuration()

    async def get_storage_configuration(self):
        if await self.has_xcc():
            return await self.immhandler.get_storage_configuration()
        return await super(OEMHandler, self).get_storage_configuration()

    async def get_video_launchdata(self):
        if await self.has_tsm():
            return await self.get_tsm_launchdata()

    async def get_tsm_launchdata(self):
        pass

    async def process_event(self, event, ipmicmd, seldata):
        if 'oemdata' in event:
            oemtype = seldata[2]
            oemdata = event['oemdata']
            if oemtype == 0xd0:  # firmware update
                event['component'] = firmware_types.get(oemdata[0], None)
                event['component_type'] = ipmiconst.sensor_type_codes[0x2b]
                slotnumber = (oemdata[1] & 0b11111000) >> 3
                if slotnumber:
                    event['component'] += ' {0}'.format(slotnumber)
                event['event'], event['severity'] = \
                    firmware_event[oemdata[1] & 0b111]
                event['event_data'] = '{0}.{1}'.format(oemdata[2], oemdata[3])
            elif oemtype == 0xd1:  # BIOS recovery
                event['severity'] = pygconst.Health.Warning
                event['component'] = 'BIOS/UEFI'
                event['component_type'] = ipmiconst.sensor_type_codes[0xf]
                status = oemdata[0]
                method = (status & 0b11110000) >> 4
                status = (status & 0b1111)
                if method == 1:
                    event['event'] = 'Automatic recovery'
                elif method == 2:
                    event['event'] = 'Manual recovery'
                if status == 0:
                    event['event'] += '- Failed'
                    event['severity'] = pygconst.Health.Failed
                if oemdata[1] == 0x1:
                    event['event'] += '- BIOS recovery image not found'
                event['event_data'] = '{0}.{1}'.format(oemdata[2], oemdata[3])
            elif oemtype == 0xd2:  # eMMC status
                if oemdata[0] == 1:
                    event['component'] = 'eMMC'
                    event['component_type'] = ipmiconst.sensor_type_codes[0xc]
                    if oemdata[0] == 1:
                        event['event'] = 'eMMC Format error'
                        event['severity'] = pygconst.Health.Failed
            elif oemtype == 0xd3:
                if oemdata[0] == 1:
                    event['event'] = 'User privilege modification'
                    event['severity'] = pygconst.Health.Ok
                    event['component'] = 'User Privilege'
                    event['component_type'] = ipmiconst.sensor_type_codes[6]
                    event['event_data'] = (
                        'User {0} on channel {1} had privilege changed '
                        'from {2} to {3}'.format(
                            oemdata[2], oemdata[1], oemdata[3] & 0b1111,
                            (oemdata[3] & 0b11110000) >> 4)
                    )
            else:
                event['event'] = 'OEM event: {0}'.format(
                    ' '.join(format(x, '02x') for x in event['oemdata']))
            del event['oemdata']
            return
        evdata = event['event_data_bytes']
        if event['event_type_byte'] == 0x75:  # ME event
            event['component'] = 'ME Firmware'
            event['component_type'] = ipmiconst.sensor_type_codes[0xf]
            event['event'], event['severity'] = me_status.get(
                evdata[1], ('Unknown', pygconst.Health.Warning))
            if evdata[1] == 3:
                event['event'], event['severity'] = me_flash_status.get(
                    evdata[2], ('Unknown state', pygconst.Health.Warning))
            elif evdata[1] == 9:
                event['event'] += ' (0x{0:2x})'.format(evdata[2])
            elif evdata[1] == 0xf and evdata[2] & 0b10000000:
                event['event'] = 'Auto configuration failed'
                event['severity'] = pygconst.Health.Critical
        # For HDD bay events, the event data 2 is the bay, modify
        # the description to be more specific
        if (event['event_type_byte'] == 0x6f
                and (evdata[0] & 0b11000000) == 0b10000000
                and event['component_type_id'] == 13):
            event['component'] += ' {0}'.format(evdata[1] & 0b11111)

    async def reseat_bay(self, bay):
        if await self.is_fpc():
            return await self.smmhandler.reseat_bay(bay)
        elif await self.has_xcc() and bay == -1:
            return await self.immhandler.reseat()
        return await super(OEMHandler, self).reseat_bay(bay)

    async def get_ntp_enabled(self):
        if await self.has_tsm() or await self.has_ami() or await self.has_asrock():
            ntpres = await self.ipmicmd.raw_command(netfn=0x32, command=0xa7)
            return ntpres['data'][0] == '\x01'
        elif await self.is_fpc():
            return self.smmhandler.get_ntp_enabled(self._fpc_variant)
        elif self.has_tsma:
            return await self.tsmahandler.get_ntp_enabled()
        return None

    async def get_ntp_servers(self):
        if await self.has_tsm() or await self.has_ami() or await self.has_asrock():
            srvs = []
            ntpres = await self.ipmicmd.raw_command(netfn=0x32, command=0xa7)
            srvs.append(ntpres['data'][1:129].rstrip('\x00'))
            srvs.append(ntpres['data'][129:257].rstrip('\x00'))
            return srvs
        if await self.is_fpc():
            return self.smmhandler.get_ntp_servers()
        if self.has_tsma:
            return await self.tsmahandler.get_ntp_servers()
        return ()

    async def set_ntp_enabled(self, enabled):
        if await self.has_tsm() or await self.has_ami() or await self.has_asrock():
            if enabled:
                await self.ipmicmd.raw_command(
                    netfn=0x32, command=0xa8, data=(3, 1), timeout=15)
            else:
                await self.ipmicmd.raw_command(
                    netfn=0x32, command=0xa8, data=(3, 0), timeout=15)
            return True
        if await self.is_fpc():
            self.smmhandler.set_ntp_enabled(enabled)
            return True
        if self.has_tsma:
            await self.tsmahandler.set_ntp_enabled(enabled)
        return None

    async def set_ntp_server(self, server, index=0):
        if await self.has_tsm() or await self.has_ami() or await self.has_asrock():
            if not (0 <= index <= 1):
                raise pygexc.InvalidParameterValue("Index must be 0 or 1")
            cmddata = bytearray((1 + index, ))
            cmddata += server.ljust(128, '\x00')
            await self.ipmicmd.raw_command(netfn=0x32, command=0xa8, data=cmddata)
            return True
        elif await self.is_fpc():
            if not 0 <= index <= 2:
                raise pygexc.InvalidParameterValue(
                    'SMM supports indexes 0 through 2')
            self.smmhandler.set_ntp_server(server, index)
            return True
        elif self.has_tsma:
            if not (0 <= index <= 1):
                raise pygexc.InvalidParameterValue("Index must be 0 or 1")
            return await self.tsmahandler.set_ntp_server(server, index)
        return None
    
    async def user_delete(self, uid, channel):
        if await self.has_xcc():
            return await self.immhandler.user_delete(uid)

    async def set_user_access(self, uid, channel, callback, link_auth, ipmi_msg,
                        privilege_level):
        if await self.is_fpc() and self._fpc_variant != 6:
            await self.smmhandler.set_user_priv(uid, privilege_level)

    async def is_fpc(self):
        """True if the target is a Lenovo nextscale fan power controller"""

        if self._fpc_variant is not None:
            return self._fpc_variant
        has_imm = await self.has_imm()
        has_xcc = await self.has_xcc()
        if has_imm or has_xcc:
            return None
        fpc_ids = ((19046, 32, 1063), (20301, 32, 462))
        smm_id = (19046, 32, 1180)
        smmv2_2u = (19046, 32, 1360)
        smmv2_6u = (19046, 32, 1387)
        currid = (self.oemid['manufacturer_id'], self.oemid['device_id'],
                  self.oemid['product_id'])
        if currid in fpc_ids:
            self._fpc_variant = 6
        elif currid == smm_id:
            self._fpc_variant = 2
        elif currid == smmv2_2u:
            self._fpc_variant = 0x22
        elif currid == smmv2_6u:
            self._fpc_variant = 0x26
        return self._fpc_variant

    @property
    def is_sd350(self):
        return (19046, 32, 13616) == (self.oemid['manufacturer_id'],
                                      self.oemid['device_id'],
                                      self.oemid['product_id'])

    tsma_ids = ((19046, 32, 1287),)

    @property
    def has_tsma(self):
        currid = (self.oemid['manufacturer_id'], self.oemid['device_id'],
                  self.oemid['product_id'])
        return currid in self.tsma_ids

    async def has_tsm(self):
        """True if this particular server have a TSM based service processor"""

        if (self.oemid['manufacturer_id'] == 19046
                and self.oemid['device_id'] == 32):
            try:
                await self.ipmicmd.raw_command(netfn=0x3a, command=0xf)
            except pygexc.IpmiException as ie:
                if ie.ipmicode == 193:
                    return False
                raise
            return True
        return False

    async def has_asrock(self):
        # True if this particular server have a ASROCKRACK
        # based service processor (RS160 or TS460)
        # RS160 (Riddler) product id is 1182 (049Eh)
        # TS460 (WildThing) product id is 1184 (04A0h)

        if (self.oemid['manufacturer_id'] == 19046
                and (self.oemid['product_id'] == 1182
                     or self.oemid['product_id'] == 1184)):
            try:
                await self.ipmicmd.raw_command(netfn=0x3a,
                                          command=0x50,
                                          data=(0x00, 0x00, 0x00))
            except pygexc.IpmiException as ie:
                if ie.ipmicode == 193:
                    return False
                raise
            return True
        return False

    @property
    def isTS460(self):
        if self.oemid['product_id'] == 1184:
            return True
        return False

    async def get_oem_inventory_descriptions(self):
        if await self.has_tsm() or await self.has_ami() or await self.has_asrock():
            # Thinkserver with TSM
            if not self.oem_inventory_info:
                async for desc in self._collect_tsm_inventory():
                    yield desc
            for compname in self.oem_inventory_info:
                yield compname
        elif await self.has_imm():
            async for desc in self.immhandler.get_hw_descriptions():
                yield desc
        elif await self.is_fpc():
            async for desc in self.smmhandler.get_inventory_descriptions(self.ipmicmd,
                                                                         await self.is_fpc()):
                yield desc

    async def get_oem_inventory(self):
        if await self.has_tsm() or await self.has_ami() or await self.has_asrock():
            await self._collect_tsm_inventory()
            for compname in self.oem_inventory_info:
                yield (compname, self.oem_inventory_info[compname])
        elif await self.has_imm():
            async for inv in self.immhandler.get_hw_inventory():
                yield inv
        elif await self.is_fpc():
            async for compname in self.smmhandler.get_inventory_descriptions(
                    self.ipmicmd, await self.is_fpc()):
                yield (compname, await self.smmhandler.get_inventory_of_component(
                    self.ipmicmd, compname))

    async def get_sensor_data(self):
        if await self.has_imm():
            async for name in self.immhandler.get_oem_sensor_names(self.ipmicmd):
                yield await self.immhandler.get_oem_sensor_reading(name,
                                                                   self.ipmicmd)
        elif await self.is_fpc():
            for name in nextscale.get_sensor_names(self.ipmicmd,
                                                   self._fpc_variant):
                yield await nextscale.get_sensor_reading(name, self.ipmicmd,
                                                         self._fpc_variant)
        elif await self.has_ami():
            async for reading in self.get_ami_sensor_data():
                yield reading

    async def get_sensor_descriptions(self):
        if await self.has_imm():
            async for desc in self.immhandler.get_oem_sensor_descriptions(self.ipmicmd):
                yield desc
        elif await self.is_fpc():
            async for desc in nextscale.get_sensor_descriptions(
                self.ipmicmd, self._fpc_variant):
                yield desc
        elif await self.has_ami():
            async for desc in self.get_ami_sensor_descriptions():
                yield desc
        if False:
            yield None

    async def get_sensor_reading(self, sensorname):
        if await self.has_imm():
            return await self.immhandler.get_oem_sensor_reading(sensorname,
                                                                self.ipmicmd)
        elif await self.is_fpc():
            return await nextscale.get_sensor_reading(sensorname, self.ipmicmd,
                                                      self._fpc_variant)
        elif await self.has_ami():
            return await self.get_ami_sensor_reading(sensorname)
        return ()

    async def get_inventory_of_component(self, component):
        if await self.has_tsm() or await self.has_ami() or await self.has_asrock():
            await self._collect_tsm_inventory()
            return self.oem_inventory_info.get(component, None)
        if await self.has_imm():
            return await self.immhandler.get_component_inventory(component)
        if await self.is_fpc():
            return await self.smmhandler.get_inventory_of_component(self.ipmicmd, component)

    async def get_cmd_type(self, categorie_item, catspec):
        if await self.has_asrock():
            cmd_type = catspec["command"]["asrock"]
        elif categorie_item in categorie_items:
            cmd_type = catspec["command"]["lenovo"]
        else:
            cmd_type = catspec["command"]

        return cmd_type

    async def _collect_tsm_inventory(self):
        self.oem_inventory_info = {}
        asrock = await self.has_asrock()
        for catid, catspec in inventory.categories.items():
            # skip the inventory fields if the system is RS160
            if asrock and catid not in categorie_items:
                continue
            if (catspec.get("workaround_bmc_bug", False)
                    and catspec["workaround_bmc_bug"](
                        "ami" if await self.has_ami() else "lenovo")):
                rsp = None
                cmd = await self.get_cmd_type(catid, catspec)
                tmp_command = dict(cmd)
                tmp_command["data"] = list(tmp_command["data"])
                count = 0
                for i in range(0x01, 0xff):
                    tmp_command["data"][-1] = i
                    try:
                        partrsp = await self.ipmicmd.raw_command(**tmp_command)
                        count += 1
                        if asrock and partrsp["data"][1] == "\xff":
                            continue

                        if rsp is None:
                            rsp = partrsp
                            rsp["data"] = list(rsp["data"])
                        else:
                            rsp["data"].extend(partrsp["data"][1:])
                    except Exception:
                        break
                # If we didn't get any response, assume we don't have
                # this category and go on to the next one
                if rsp is None:
                    continue
                rsp["data"].insert(1, count)
                rsp["data"] = buffer(bytearray(rsp["data"]))
            else:
                try:
                    cmd = await self.get_cmd_type(catid, catspec)
                    rsp = await self.ipmicmd.raw_command(**cmd)
                except pygexc.IpmiException:
                    continue
            # Parse the response we got
            try:
                items = inventory.parse_inventory_category(
                    catid, rsp, asrock,
                    countable=catspec.get("countable", True)
                )
            except Exception:
                # If we can't parse an inventory category, ignore it
                print(traceback.print_exc())
                continue

            for item in items:
                try:
                    # Originally on ThinkServer and SD350 (Kent),
                    # the DIMM is distinguished by slot,
                    # the key is the value of slot number (item["index"])
                    # While on RS160/TS460 the DIMMs is distinguished
                    # by slot number and channel number,
                    # the key is the value of the sum of slot number
                    # and channel number
                    if asrock and catid == "dimm":
                        if item["channel_number"] == 1:
                            key = catspec["idstr"].format(item["index"])
                        else:
                            key = catspec["idstr"].format(
                                item["index"] + item["channel_number"])
                    else:
                        key = catspec["idstr"].format(item["index"])

                    del item["index"]
                    self.oem_inventory_info[key] = item
                except Exception:
                    # If we can't parse an inventory item, ignore it
                    print(traceback.print_exc())
                    continue

    async def get_leds(self):
        cmd = 0x02
        led_set = leds
        led_set_status = led_status

        asrock = await self.has_asrock()
        if await self.has_ami():
            cmd = 0x05
            led_set = ami_leds
            led_set_status = ami_led_status
        elif asrock:
            cmd = 0x50
            # because rs160 has different led info with ts460
            if self.isTS460:
                led_set = ts460_leds
            else:
                led_set = asrock_leds
            led_set_status = asrock_led_status

        for (name, id_) in led_set.items():
            try:
                if asrock:
                    rsp = await self.ipmicmd.raw_command(netfn=0x3A, command=cmd,
                                                    data=(0x03, id_, 0x00))
                    rdata = bytearray(rsp['data'][:])
                    status = rdata[1]
                else:
                    rsp = await self.ipmicmd.raw_command(netfn=0x3A, command=cmd,
                                                    data=(id_,))
                    rdata = bytearray(rsp['data'][:])
                    status = rdata[0]

            except pygexc.IpmiException:
                continue  # Ignore LEDs we can't retrieve
            status = led_set_status.get(status,
                                        led_status_default)
            yield (name, {'status': status})

    async def set_identify(self, on, duration, blink):
        if on and not duration and self.is_sd350:
            await self.ipmicmd.raw_command(netfn=0x3a, command=6, data=(1, 1))
        elif await self.has_xcc():
            await self.immhandler.set_identify(on, duration, blink)
        else:
            raise pygexc.UnsupportedFunctionality()

    async def process_fru(self, fru, name=None):
        if fru is None:
            return fru
        if await self.has_tsm():
            fru['oem_parser'] = 'lenovo'
            # Thinkserver lays out specific interpretation of the
            # board extra fields
            try:
                _, _, wwn1, wwn2, mac1, mac2 = fru['board_extra']
                if wwn1 not in ('0000000000000000', ''):
                    fru['WWN 1'] = wwn1.encode('utf-8')
                if wwn2 not in ('0000000000000000', ''):
                    fru['WWN 2'] = wwn2.encode('utf-8')
                if mac1 not in ('00:00:00:00:00:00', ''):
                    fru['MAC Address 1'] = mac1.encode('utf-8')
                if mac2 not in ('00:00:00:00:00:00', ''):
                    fru['MAC Address 2'] = mac2.encode('utf-8')
            except (AttributeError, KeyError):
                pass
            try:
                # The product_extra field is UUID as the system would present
                # in DMI.  This is different than the two UUIDs that
                # it returns for get device and get system uuid...
                byteguid = fru['product_extra'][0]
                # It can present itself as claiming to be ASCII when it
                # is actually raw hex.  As a result it triggers the mechanism
                # to strip \x00 from the end of text strings.  Work around this
                # by padding with \x00 to the right if less than 16 long
                byteguid.extend('\x00' * (16 - len(byteguid)))
                if byteguid not in ('\x20' * 16, '\x00' * 16, '\xff' * 16):
                    fru['UUID'] = util.decode_wireformat_uuid(byteguid)
            except (AttributeError, KeyError, IndexError):
                pass
            return fru
        elif await self.has_imm():
            fru['oem_parser'] = 'lenovo'
            try:
                bextra = fru['board_extra']
                fru['FRU Number'] = bextra[0]
                fru['Revision'] = bextra[4]
                macs = bextra[6]
                if macs:
                    macprefix = None
                    idx = 0
                    endidx = len(macs) - 5
                    macprefix = None
                    while idx < endidx:
                        currmac = macs[idx:idx + 6]
                        if not isinstance(currmac, bytearray):
                            # invalid vpd format, abort attempts to extract
                            # mac in this way
                            break
                        if currmac == b'\x00\x00\x00\x00\x00\x00':
                            break
                        # VPD may veer off, detect and break off
                        if macprefix is None:
                            macprefix = currmac[:3]
                        elif currmac[:3] != macprefix:
                            break
                        ms = mac_format.format(*currmac)
                        ifidx = idx / 6 + 1
                        fru['MAC Address {0}'.format(ifidx)] = ms
                        idx = idx + 6
            except (AttributeError, KeyError, IndexError):
                pass
            if await self.has_xcc() and name and name.startswith('PSU '):
                self.immhandler.augment_psu_info(fru, name)
            if (await self.has_xcc() and 'memory_type' in fru
                    and fru['memory_type'] == 'Unknown'):
                await self.immhandler.fetch_dimm(name, fru)
            return fru
        elif await self.is_fpc() and await self.is_fpc() != 6:  # SMM variant
            fru['oem_parser'] = 'lenovo'
            return await self.smmhandler.process_fru(fru)
        elif await self.has_asrock():
            fru['oem_parser'] = 'lenovo'
            # ASRock RS160 TS460 lays out specific interpretation of the
            # board extra fields
            try:
                mac1 = fru['board_extra']
                if mac1 not in ('00:00:00:00:00:00', ''):
                    fru['MAC Address 1'] = mac1.encode('utf-8')
            except (AttributeError, KeyError):
                pass
            return fru
        else:
            fru['oem_parser'] = None
            return fru

    async def has_xcc(self):
        if self._hasxcc is not None:
            return self._hasxcc
        try:
            bdata = await self.ipmicmd.raw_command(netfn=0x3a, command=0xc1)
        except pygexc.IpmiException:
            self._hasxcc = False
            self._hasimm = False
            return False
        if len(bdata['data'][:]) != 3:
            self._hasimm = False
            self._hasxcc = False
            return False
        rdata = bytearray(bdata['data'][:])
        self._hasxcc = rdata[1] & 16 == 16
        if self._hasxcc:
            # For now, have imm calls go to xcc, since they are providing same
            # interface.  Longer term the hope is that all the Lenovo
            # stuff will branch at init, and not have conditionals
            # in all the functions
            self._hasimm = self._hasxcc
        return self._hasxcc

    async def has_imm(self):
        if self._hasimm is not None:
            return self._hasimm
        try:
            bdata = await self.ipmicmd.raw_command(netfn=0x3a, command=0xc1)
        except pygexc.IpmiException:
            self._hasimm = False
            return False
        if len(bdata['data'][:]) != 3:
            self._hasimm = False
            return False
        rdata = bytearray(bdata['data'][:])
        self._hasimm = (rdata[1] & 1 == 1) or (rdata[1] & 16 == 16)
        return self._hasimm

    async def has_ami(self):
        """True if this particular server is AMI based lenovo server

        """
        if(self.oemid['manufacturer_id'] == 19046
                and self.oemid['product_id'] == 13616):
            try:
                rsp = await self.ipmicmd.raw_command(netfn=0x3a, command=0x80)
            except pygexc.IpmiException as ie:
                if ie.ipmicode == 193:
                    return False
                raise
            rdata = bytearray(rsp['data'][:])
            if rdata[0] in range(5):
                return True
            else:
                return False
        return False

    async def get_oem_firmware(self, bmcver, components, category):
        if await self.has_tsm() or await self.has_ami() or await self.has_asrock():
            command = firmware.get_categories()["firmware"]
            fw_cmd = await self.get_cmd_type("firmware", command)
            rsp = await self.ipmicmd.raw_command(**fw_cmd)

            # the newest Lenovo ThinkServer versions are returning Bios version
            # numbers through another command
            bios_versions = None
            if await self.has_tsm() or await self.has_asrock():
                bios_command = firmware.get_categories()["bios_version"]
                bios_cmd = await self.get_cmd_type("bios_version", bios_command)
                bios_rsp = await self.ipmicmd.raw_command(**bios_cmd)
                if await self.has_asrock():
                    bios_versions = bios_rsp['data']
                else:
                    bios_versions = bios_command["parser"](bios_rsp['data'])
            # pass bios versions to firmware parser
            for x in command["parser"](rsp["data"],
                                     bios_versions,
                                     await self.has_asrock()):
                yield x
        elif await self.has_imm():
            async for x in self.immhandler.get_firmware_inventory(bmcver, components, category):
                yield x
        elif await self.is_fpc():
            async for x in nextscale.get_fpc_firmware(bmcver, self.ipmicmd,
                                                     self._fpc_variant):
                yield x
        elif self.has_tsma:
            async for x in self.tsmahandler.get_firmware_inventory(
                components, raisebypass=False, ipmicmd=self.ipmicmd):
                yield x
        async for x in super(OEMHandler, self).get_oem_firmware(bmcver, components, category):
            yield x

    async def get_diagnostic_data(self, savefile, progress, autosuffix=False):
        if await self.has_xcc():
            return await self.immhandler.get_diagnostic_data(savefile, progress,
                                                       autosuffix)
        if await self.is_fpc():
            return await self.smmhandler.get_diagnostic_data(savefile, progress,
                                                       autosuffix,
                                                       self._fpc_variant)
        if self.has_tsma:
            return await self.tsmahandler.get_diagnostic_data(savefile, progress,
                                                        autosuffix)

    async def get_oem_capping_enabled(self):
        if await self.has_tsm():
            rsp = await self.ipmicmd.raw_command(netfn=0x3a, command=0x1b,
                                            data=(3,))
            # disabled
            if rsp['data'][0] == '\x00':
                return False
            # enabled
            else:
                return True

    async def set_oem_capping_enabled(self, enable):
        """Set PSU based power capping

        :param enable: True for enable and False for disable
        """
        # 1 - Enable power capping(default)
        if enable:
            statecode = 1
        # 0 - Disable power capping
        else:
            statecode = 0
        if await self.has_tsm():
            await self.ipmicmd.raw_command(netfn=0x3a, command=0x1a,
                                      data=(3, statecode))
            return True

    async def get_oem_remote_kvm_available(self):
        if await self.has_tsm():
            rsp = await self.ipmicmd.raw_command(netfn=0x3a, command=0x13)
            return rsp['data'][0] == 0
        return False

    async def _restart_dns(self):
        if await self.has_tsm():
            await self.ipmicmd.raw_command(netfn=0x32, command=0x6c, data=(7, 0))

    async def get_oem_domain_name(self):
        if await self.has_tsm():
            name = ''
            for i in range(1, 5):
                rsp = await self.ipmicmd.raw_command(netfn=0x32, command=0x6b,
                                                data=(4, i))
                name += rsp['data'][:]
            return name.rstrip('\x00')
        elif await self.is_fpc():
            return self.smmhandler.get_domain()

    async def set_oem_domain_name(self, name):
        if await self.has_tsm():
            # set the domain name length
            data = [3, 0, 0, 0, 0, len(name)]
            await self.ipmicmd.raw_command(netfn=0x32, command=0x6c, data=data)

            # set the domain name content
            name = name.ljust(256, "\x00")
            for i in range(0, 4):
                data = [4, i + 1]
                offset = i * 64
                data.extend([ord(x) for x in name[offset:offset + 64]])
                await self.ipmicmd.raw_command(netfn=0x32, command=0x6c, data=data)

            await self._restart_dns()
            return
        elif await self.is_fpc():
            self.smmhandler.set_domain(name)

    async def set_hostname(self, hostname):
        if await self.has_xcc():
            return await self.immhandler.set_hostname(hostname)
        elif await self.is_fpc():
            return self.smmhandler.set_hostname(hostname)
        return await super(OEMHandler, self).set_hostname(hostname)

    async def get_hostname(self):
        if await self.has_xcc():
            return await self.immhandler.get_hostname()
        elif await self.is_fpc():
            return self.smmhandler.get_hostname()
        return await super(OEMHandler, self).get_hostname()

    """ Gets a remote console launcher for a Lenovo ThinkServer.

    Returns a tuple: (content type, launcher) or None if the launcher could
    not be retrieved."""
    async def _get_ts_remote_console(self, bmc, username, password):
        # We don't establish non-secure connections without checking
        # certificates
        if not self.ipmicmd.certverify:
            return
        conn = wc.WebConnection(bmc, 443,
                                       verifycallback=self.ipmicmd.certverify)
        conn.connect()
        params = urlencode({
            'WEBVAR_USERNAME': username,
            'WEBVAR_PASSWORD': password
        })
        headers = {
            'Connection': 'keep-alive'
        }
        rsp = await conn.grab_response_with_status('/rpc/WEBSES/create.asp', params, headers=headers)

        if rsp[1] == 200:
            conn.cookies = {}
            body = rsp[0].decode().split('\n')
            session_line = None
            for line in body:
                if 'SESSION_COOKIE' in line:
                    session_line = line
            if session_line is None:
                return

            session_id = session_line.split('\'')[3]
            # Usually happens when maximum number of sessions is reached
            if session_id == 'Failure_Session_Creation':
                return

            headers = {
                'Connection': 'keep-alive',
                'Cookie': 'SessionCookie=' + session_id,
            }
            rsp = await conn.grab_response_with_status('/Java/jviewer.jnlp?EXTRNIP=' + bmc + '&JNLPSTR=JViewer', headers=headers)
            if rsp[1] == 200:
                return rsp[2]['Content-Type'], base64.b64encode(
                    rsp[0])

    async def get_graphical_console(self):
        return await self._get_ts_remote_console(self.ipmicmd.bmc,
                                                 self.ipmicmd.ipmi_session.userid,
                                                 self.ipmicmd.ipmi_session.password)

    async def add_extra_net_configuration(self, netdata, channel=None):
        if await self.has_tsm():
            ipv6_addr = await self.ipmicmd.raw_command(
                netfn=0x0c, command=0x02,
                data=(0x01, 0xc5, 0x00, 0x00))["data"][1:]
            if not ipv6_addr:
                return
            rspdata = await self.ipmicmd.raw_command(
                netfn=0xc, command=0x02,
                data=(0x1, 0xc6, 0, 0))['data']
            ipv6_prefix_ba = bytearray(rspdata)
            ipv6_prefix = ipv6_prefix_ba[1]

            if hasattr(socket, 'inet_ntop'):
                ipv6str = socket.inet_ntop(socket.AF_INET6, ipv6_addr)
            else:
                # fall back to a dumber, but more universal formatter
                ipv6str = binascii.b2a_hex(ipv6_addr)
                ipv6str = ':'.join([ipv6str[x:x + 4] for x in range(0, 32, 4)])
            netdata['ipv6_addresses'] = [
                '{0}/{1}'.format(ipv6str, ipv6_prefix)]

    async def has_megarac(self):
        # if there is functionality that is the same for tsm or generic
        # megarac, then this is appropriate.  If there's a TSM specific
        # preferred, use has_tsm first
        if self._has_megarac is not None:
            return self._has_megarac
        self._has_megarac = False
        try:
            rsp = await self.ipmicmd.raw_command(netfn=0x32, command=0x7e)
            # We don't have a handy classify-only, so use get sel policy
            # rsp should have a length of one, and be either '\x00' or '\x01'
            if len(rsp['data'][:]) == 1 and rsp['data'][0] in ('\x00', '\x01'):
                self._has_megarac = True
        except pygexc.IpmiException as ie:
            if ie.ipmicode == 0:
                # if it's a generic IpmiException rather than an error code
                # from the BMC, then this is a deeper problem than just an
                # invalid command or command length or similar
                raise
        return self._has_megarac

    async def set_alert_ipv6_destination(self, ip, destination, channel):
        if await self.has_megarac():
            ethidx = await self._megarac_eth_index()
            reqdata = bytearray([channel, 193, destination, ethidx, 0])
            parsedip = socket.inet_pton(socket.AF_INET6, ip)
            reqdata.extend(parsedip)
            reqdata.extend('\x00\x00\x00\x00\x00\x00')
            await self.ipmicmd.raw_command(netfn=0xc, command=1, data=reqdata)
            return True
        return False

    async def _set_short_ris_string(self, selector, value):
        data = (1, selector, 0) + struct.unpack('{0}B'.format(len(value)),
                                                value)
        await self.ipmicmd.raw_command(netfn=0x32, command=0x9f, data=data)

    async def _set_ris_string(self, selector, value):
        if len(value) > 256:
            raise pygexc.UnsupportedFunctionality(
                'Value exceeds 256 characters: {0}'.format(value))
        padded = value + (256 - len(value)) * '\x00'
        padded = list(struct.unpack('256B', padded))
        # 8 = RIS, 4 = hd, 2 = fd, 1 = cd
        try:  # try and clear in-progress if left incomplete
            await self.ipmicmd.raw_command(netfn=0x32, command=0x9f,
                                      data=(1, selector, 0, 0))
        except pygexc.IpmiException:
            pass
        # set in-progress
        await self.ipmicmd.raw_command(netfn=0x32, command=0x9f,
                                  data=(1, selector, 0, 1))
        # now do the set
        for x in range(0, 256, 64):
            currdata = padded[x:x + 64]
            currchunk = x // 64 + 1
            cmddata = [1, selector, currchunk] + currdata
            await self.ipmicmd.raw_command(netfn=0x32, command=0x9f, data=cmddata)
        # unset in-progress
        await self.ipmicmd.raw_command(netfn=0x32, command=0x9f,
                                  data=(1, selector, 0, 0))

    async def _megarac_fetch_image_shortnames(self):
        rsp = await self.ipmicmd.raw_command(netfn=0x32, command=0xd8,
                                        data=(7, 1, 0))
        imgnames = rsp['data'][1:]
        shortnames = []
        for idx in range(0, len(imgnames), 22):
            shortnames.append(imgnames[idx + 2:idx + 22].rstrip('\0'))
        return shortnames

    async def _megarac_media_waitforready(self, imagename):
        # first, we have, sadly, a 10 second grace period for some invisible
        # async activity to get far enough long to monitor
        await self.ipmicmd.ipmi_session.pause(10)
        risenabled = '\x00'
        mountok = '\xff'
        while risenabled != '\x01':
            risenabled = (await self.ipmicmd.raw_command(
                netfn=0x32, command=0x9e, data=(8, 10)))['data'][2]
        while mountok == '\xff':
            mountok = (await self.ipmicmd.raw_command(
                netfn=0x32, command=0x9e, data=(1, 8)))['data'][2]
        targshortname = _megarac_abbrev_image(imagename)
        shortnames = await self._megarac_fetch_image_shortnames()
        while targshortname not in shortnames:
            await self.ipmicmd.wait_for_rsp(1)
            shortnames = await self._megarac_fetch_image_shortnames()
        await self.ipmicmd.ipmi_session.pause(10)
        try:
            await self.ipmicmd.raw_command(netfn=0x32, command=0xa0, data=(1, 0))
            await self.ipmicmd.ipmi_session.pause(5)
        except pygexc.IpmiException:
            pass

    async def _megarac_attach_media(self, proto, username, password, imagename,
                              domain, path, host):
        # First we must ensure that the RIS is actually enabled
        await self.ipmicmd.raw_command(netfn=0x32, command=0x9f, data=(8, 10, 0, 1))
        if username is not None:
            await self._set_ris_string(3, username)
        if password is not None:
            await self._set_short_ris_string(4, password)
        if domain is not None:
            await self._set_ris_string(6, domain)
        await self._set_ris_string(1, path)
        ip = util.get_ipv4(host)[0]
        await self._set_short_ris_string(2, ip)
        await self._set_short_ris_string(5, proto)
        # now to restart RIS to have changes take effect...
        await self.ipmicmd.raw_command(netfn=0x32, command=0x9f, data=(8, 11))
        # now to kick off the requested mount
        await self._megarac_media_waitforready(imagename)
        await self._set_ris_string(0, imagename)
        await self.ipmicmd.raw_command(netfn=0x32, command=0xa0,
                                  data=(1, 1))

    async def attach_remote_media(self, url, username, password):
        if await self.has_imm():
            await self.immhandler.attach_remote_media(url, username, password)
        elif self.has_tsma:
            return await self.tsmahandler.attach_remote_media(
                url, username, password, None)
        elif await self.has_megarac():
            proto, host, path = util.urlsplit(url)
            if proto == 'smb':
                proto = 'cifs'
            domain = None
            path, imagename = path.rsplit('/', 1)
            if username is not None and '@' in username:
                username, domain = username.split('@', 1)
            elif username is not None and '\\' in username:
                domain, username = username.split('\\', 1)
            try:
                await self._megarac_attach_media(proto, username, password,
                                           imagename, domain, path, host)
            except pygexc.IpmiException as ie:
                if ie.ipmicode in (0x92, 0x99):
                    # if starting from scratch, this can happen...
                    await self._megarac_attach_media(proto, username, password,
                                               imagename, domain, path, host)
                else:
                    raise

    async def get_update_status(self):
        if await self.is_fpc() or self.has_tsma:
            return "ready"
        if await self.has_xcc():
            return await self.immhandler.get_update_status()
        return await super(OEMHandler, self).get_update_status()

    async def update_firmware(self, filename, data=None, progress=None, bank=None):
        if await self.has_xcc():
            return await self.immhandler.update_firmware(
                filename, data=data, progress=progress, bank=bank)
        if await self.is_fpc():
            return await self.smmhandler.update_firmware(
                filename, data=data, progress=progress, bank=bank)
        if self.has_tsma:
            return await self.tsmahandler.update_firmware(
                filename, data=data, progress=progress, bank=bank)
        return await super(OEMHandler, self).update_firmware(filename, data=data,
                                                       progress=progress,
                                                       bank=bank)

    async def get_description(self):
        if await self.has_xcc():
            return await self.immhandler.get_description()
        if await self.is_fpc():
            return {'height': self._fpc_variant & 0xf, 'slot': 0}
        return await super(OEMHandler, self).get_description()

    async def get_extended_bmc_configuration(self):
        if await self.has_xcc():
            return await self.immhandler.get_extended_bmc_configuration()
        return await super(OEMHandler, self).get_extended_bmc_configuration()

    async def get_bmc_configuration(self):
        if await self.has_xcc():
            return await self.immhandler.get_bmc_configuration()
        if await self.is_fpc():
            return await self.smmhandler.get_bmc_configuration(self._fpc_variant)
        if self.has_tsma:
            return await self.tsmahandler.get_bmc_configuration()
        return await super(OEMHandler, self).get_bmc_configuration()

    async def set_bmc_configuration(self, changeset):
        if await self.has_xcc():
            return await self.immhandler.set_bmc_configuration(changeset)
        if await self.is_fpc():
            return await self.smmhandler.set_bmc_configuration(
                changeset, self._fpc_variant)
        if self.has_tsma:
            return await self.tsmahandler.set_bmc_configuration(
                changeset)
        return await super(OEMHandler, self).set_bmc_configuration(changeset)

    async def get_system_configuration(self, hideadvanced):
        if await self.has_imm() or await self.has_xcc():
            return await self.immhandler.get_system_configuration(hideadvanced)
        if self.has_tsma:
            return await self.tsmahandler.get_uefi_configuration(hideadvanced)
        return await super(OEMHandler, self).get_system_configuration(hideadvanced)

    async def set_system_configuration(self, changeset):
        if await self.has_imm() or await self.has_xcc():
            return await self.immhandler.set_system_configuration(changeset)
        if self.has_tsma:
            return await self.tsmahandler.set_uefi_configuration(changeset)
        return await super(OEMHandler, self).set_system_configuration(changeset)

    async def clear_bmc_configuration(self):
        if await self.has_xcc():
            return await self.immhandler.clear_bmc_configuration()
        elif await self.is_fpc():
            return await self.smmhandler.clear_bmc_configuration()
        elif self.has_tsma:
            return await self.tsmahandler.clear_bmc_configuration()
        return await super(OEMHandler, self).clear_system_configuration()

    async def clear_system_configuration(self):
        if await self.has_xcc():
            return await self.immhandler.clear_system_configuration()
        if self.has_tsma:
            return await self.tsmahandler.clear_uefi_configuration()
        return await super(OEMHandler, self).clear_system_configuration()

    async def detach_remote_media(self):
        if await self.has_imm():
            await self.immhandler.detach_remote_media()
        elif self.has_tsma:
            await self.tsmahandler.detach_remote_media()
        elif await self.has_megarac():
            await self.ipmicmd.raw_command(
                netfn=0x32, command=0x9f, data=(8, 10, 0, 0))
            await self.ipmicmd.raw_command(netfn=0x32, command=0x9f, data=(8, 11))

    async def upload_media(self, filename, progress, data):
        if await self.has_xcc() or await self.has_imm():
            return await self.immhandler.upload_media(filename, progress, data)
        return await super(OEMHandler, self).upload_media(filename, progress, data)

    async def list_media(self):
        if await self.has_xcc() or await self.has_imm():
            async for x in self.immhandler.list_media():
                yield x
            return
        if self.has_tsma:
            async for x in self.tsmahandler.list_media():
                yield x
            return
        async for x in super(OEMHandler, self).list_media():
            yield x

    async def get_health(self, summary):
        if await self.has_xcc():
            return await self.immhandler.get_health(summary)
        return await super(OEMHandler, self).get_health(summary)

    async def get_licenses(self):
        if await self.has_xcc():
            async for x in self.immhandler.get_licenses():
                yield x
            return
        async for x in super(OEMHandler, self).get_licenses():
            yield x

    async def get_user_expiration(self, uid):
        if await self.has_xcc():
            return await self.immhandler.get_user_expiration(uid)
        return None

    async def delete_license(self, name):
        if await self.has_xcc():
            return await self.immhandler.delete_license(name)
        return await super(OEMHandler, self).delete_license(name)

    async def save_licenses(self, directory):
        if await self.has_xcc():
            async for x in self.immhandler.save_licenses(directory):
                yield x
            return
        async for x in super(OEMHandler, self).save_licenses(directory):
            yield x

    async def apply_license(self, filename, progress=None, data=None):
        if await self.has_xcc():
            async for x in self.immhandler.apply_license(filename, progress, data):
                yield x
            return
        async for x in super(OEMHandler, self).apply_license(filename, progress, data):
            yield x

    async def set_oem_extended_privilleges(self, uid):
        """Set user extended privillege as 'KVM & VMedia Allowed'

        |KVM & VMedia Not Allowed	0x00 0x00 0x00 0x00
        |KVM Only Allowed	0x01 0x00 0x00 0x00
        |VMedia Only Allowed	0x02  0x00 0x00 0x00
        |KVM & VMedia Allowed	0x03 0x00 0x00 0x00

        :param uid: User ID.
        """
        if await self.has_tsm():
            await self.ipmicmd.raw_command(netfn=0x32, command=0xa3, data=(
                uid, 0x03, 0x00, 0x00, 0x00))
            return True
        return False

    async def get_user_privilege_level(self, uid):
        if await self.has_xcc():
            return await self.immhandler.get_user_privilege_level(uid)
        return None

    async def set_user_access(self, uid, channel, callback, link_auth, ipmi_msg, privilege_level):
        if await self.has_xcc():
            await self.immhandler.set_user_access(uid, privilege_level)

    async def process_zero_fru(self, zerofru):
        if (self.oemid['manufacturer_id'] == 19046
                and self.oemid['product_id'] == 13616):
            # Currently SD350 FRU UUID is synchronized with the Device UUID.
            # Need to change to System UUID in future.
            # Since the IPMI get device uuid matches SMBIOS,
            # no need to decode it.
            guiddata = await self.ipmicmd.raw_command(netfn=6, command=0x8)
            if 'error' not in guiddata:
                zerofru['UUID'] = util.decode_wireformat_uuid(
                    guiddata['data'], True)
        else:
            # It is expected that a manufacturer matches SMBIOS to IPMI
            # get system uuid return data.  If a manufacturer does not
            # do so, they should handle either deletion or fixup in the
            # OEM processing pass.  Code optimistically assumes that if
            # data is returned, than the vendor is properly using it.

            guiddata = await self.ipmicmd.raw_command(netfn=6, command=0x37)
            if 'error' not in guiddata:
                if (self.oemid['manufacturer_id'] == 19046
                        and (self.oemid['product_id'] == 1182
                             or self.oemid['product_id'] == 1184)):
                    # The manufacturer (Asrockrack) of RS160/TS460
                    # matches SMBIOS
                    # to IPMI get system uuid return data,
                    # no need to decode it.
                    zerofru['UUID'] = util.decode_wireformat_uuid(
                        guiddata['data'], True)
                else:
                    zerofru['UUID'] = util.decode_wireformat_uuid(
                        guiddata['data'])
        if await self.is_fpc():
            await self.smmhandler.augment_zerofru(zerofru, self._fpc_variant)
        return await self.process_fru(zerofru)

    async def get_ami_sensor_reading(self, sensorname):
        """Get an OEM sensor

        If software wants to model some OEM behavior as a 'sensor' without
        doing SDR, this hook provides that ability.  It should mimic
        the behavior of 'get_sensor_reading' in command.py.
        """
        async for sensor in self.get_sensor_data():
            if sensor.name == sensorname:
                return sensor

    async def get_ami_sensor_descriptions(self):
        """Get list of OEM sensor names and types

        Iterate over dicts describing a label and type for OEM 'sensors'.  This
        should mimic the behavior of the get_sensor_descriptions function
        in command.py.
        """
        if await self.has_ami():
            energy_sensor = energy.Energy(self.ipmicmd)
            async for sensor in energy_sensor.get_energy_sensor():
                yield {'name': sensor.name,
                       'type': sensor.type}

    async def get_ami_sensor_data(self):
        """Get OEM sensor data

        Iterate through all OEM 'sensors' and return data as if they were
        normal sensors.  This should mimic the behavior of the get_sensor_data
        function in command.py.
        """
        if await self.has_ami():
            energy_sensor = energy.Energy(self.ipmicmd)
            async for sensor in energy_sensor.get_energy_sensor():
                yield sensor
