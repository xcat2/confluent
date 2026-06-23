# Copyright 2016-2017 Lenovo
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
import fnmatch
import struct
import weakref
from xml.etree.ElementTree import fromstring as rfromstring
import zipfile


import aiohmi.constants as pygconst
import aiohmi.exceptions as pygexc
import aiohmi.ipmi.private.session as ipmisession
import aiohmi.ipmi.private.util as util
from aiohmi.ipmi import sdr
import aiohmi.util.webclient as webclient
from urllib.parse import urlencode


psutypes = {
    0x63: 'CFF v3 550W PT',
    0x64: 'CFF v3 750W PT',
    0x65: 'CFF v3 750W TT',
    0x66: 'CFF v3 1100W PT',
    0x67: 'CFF v3 1600W PT',
    0x68: 'CFF v3 2000W PT',
    0x6B: 'CFF v4 500W PT',
    0x6C: 'CFF v4 750W PT',
    0x6D: 'CFF v4 750W TT',
    0x6E: 'CFF v4 1100W PT',
    0x6F: 'CFF v4 1100W -48Vdc',
    0x70: 'CFF v4 1100W 200-277Vac/240-380Vdc',
    0x71: 'CFF v4 1800W PT',
    0x72: 'CFF v4 2400W PT',
}


def fromstring(inputdata):
    if b'!entity' in inputdata.lower():
        raise Exception('!ENTITY not supported in this interface')
    return rfromstring(inputdata)


def stringtoboolean(originput, name):
    input = originput.lower()
    try:
        num = int(input)
    except ValueError:
        num = None
    if 'enabled'.startswith(input) or 'yes'.startswith(input) or num == 1:
        return True
    elif 'disabled'.startswith(input) or 'no'.startswith(input) or num == 0:
        return False
    raise pygexc.InvalidParameterValue('{0} is an invalid setting for '
                                       '{1}'.format(originput, name))


async def fpc_read_ac_input(ipmicmd):
    rsp = await ipmicmd.raw_command(netfn=0x32, command=0x90, data=(1,))
    rsp = rsp['data']
    if len(rsp) == 6:
        rsp = b'\x00' + bytes(rsp)
    return struct.unpack_from('<H', rsp[3:5])[0]


async def fpc_read_dc_output(ipmicmd):
    rsp = await ipmicmd.raw_command(netfn=0x32, command=0x90, data=(2,))
    rsp = rsp['data']
    if len(rsp) == 6:
        rsp = b'\x00' + bytes(rsp)
    return struct.unpack_from('<H', rsp[3:5])[0]


async def fpc_read_fan_power(ipmicmd):
    rsp = await ipmicmd.raw_command(netfn=0x32, command=0x90, data=(3,))
    rsp = bytes(rsp['data'])
    rsp += b'\x00'
    return struct.unpack_from('<I', rsp[1:])[0] / 100.0


async def fpc_read_psu_fan(ipmicmd, number, sz):
    rsp = await ipmicmd.raw_command(netfn=0x32, command=0xa5, data=(number,))
    rsp = bytes(rsp['data'])
    if len(rsp) > 5:
        return struct.unpack_from('<H', rsp[2:4])[0]
    else:
        return struct.unpack_from('<H', rsp[:2])[0]


async def fpc_get_psustatus(ipmicmd, number, sz):
    rsp = await ipmicmd.raw_command(netfn=0x32, command=0x91)
    mask = 1 << (number - 1)
    rsp['data'] = bytearray(rsp['data'])
    if len(rsp['data']) >= 10:
        tmpdata = rsp['data']
        rsp['data'] = list(struct.unpack('<HHHHBB', tmpdata[:10]))
    if len(rsp['data']) == 6:
        statdata = [0]
    else:
        statdata = []
    statdata += rsp['data']
    presence = statdata[3] & mask == mask
    pwrgood = statdata[4] & mask == mask
    throttle = (statdata[6] | statdata[2]) & mask == mask
    health = pygconst.Health.Ok
    states = []
    if presence and not pwrgood:
        health = pygconst.Health.Critical
        states.append('Power input lost')
    if throttle:
        health = pygconst.Health.Critical
        states.append('Throttled')
    if presence:
        states.append('Present')
    else:
        states.append('Absent')
        health = pygconst.Health.Critical
    return (health, states)


async def fpc_get_nodeperm(ipmicmd, number, sz):
    try:
        rsp = await ipmicmd.raw_command(netfn=0x32, command=0xa7, data=(number,))
    except pygexc.IpmiException as ie:
        if ie.ipmicode == 0xd5:  # no node present
            return (pygconst.Health.Ok, ['Absent'])
        raise
    health = pygconst.Health.Ok
    states = []
    if len(rsp['data']) == 4:  # different gens handled rc differently
        rsp['data'] = b'\x00' + bytes(rsp['data'])
    elif len(rsp['data']) == 6:  # New FPC format
        rsp['data'] = bytes(rsp['data'][:2]) + bytes(rsp['data'][3:])
    permdata = bytearray(rsp['data'])
    perminfo = permdata[1]
    if sz == 6:  # FPC
        permfail = (2, 3)
    else:  # SMM
        permfail = (2,)
    if perminfo & 0x20:
        if permdata[4] in permfail:
            states.append('Insufficient Power')
            health = pygconst.Health.Failed
        elif rsp['data'][3:5] != '\x00\x00' and permdata[4] not in (0, 1):
            states.append('No Power Permission')
            health = pygconst.Health.Failed
    if perminfo & 0x40:
        states.append('Node Fault')
        health = pygconst.Health.Failed
    if rsp['data'][3:5] == '\x00\x00' or permdata[4] == 0:
        states.append('Absent')
    return (health, states)


async def fpc_read_powerbank(ipmicmd):
    rsp = await ipmicmd.raw_command(netfn=0x32, command=0xa2)
    return struct.unpack_from('<H', rsp['data'][3:])[0]


async def get_psu_count(ipmicmd, variant):
    if variant == 0x26:
        mymsg = await ipmicmd.raw_command(netfn=0x32, command=0xa8)
        builddata = bytearray(mymsg['data'])
        if builddata[13] in (3, 6):
            return 9
        else:
            return 6
    else:
        return variant & 0xf


async def fpc_get_dripstatus(ipmicmd, number, sz):
    health = pygconst.Health.Ok
    states = []
    rsp = await ipmicmd.raw_command(0x34, 5)
    rdata = bytearray(rsp['data'])
    number = number - 1
    if rdata[0] & (1 << number) == 0:
        states.append('Absent')
        health = pygconst.Health.Critical
    if rdata[1] & (1 << number) != 0:
        states.append('Leak detected')
        health = pygconst.Health.Critical
    return (health, states)


fpc_sensors = {
    'AC Power': {
        'type': 'Power',
        'units': 'W',
        'provider': fpc_read_ac_input,
    },
    'DC Power': {
        'type': 'Power',
        'units': 'W',
        'provider': fpc_read_dc_output,
    },
    'PSU Power Loss': {
        'type': 'Power',
        'units': 'W',
        'provider': fpc_read_dc_output,
    },
    'Fan Power': {
        'type': 'Power',
        'units': 'W',
        'provider': fpc_read_fan_power
    },
    'PSU Fan Speed': {
        'type': 'Fan',
        'units': 'RPM',
        'provider': fpc_read_psu_fan,
        'elementsfun': get_psu_count,
    },
    'Total Power Capacity': {
        'type': 'Power',
        'units': 'W',
        'provider': fpc_read_powerbank,
    },
    'Node Power Permission': {
        'type': 'Management Subsystem Health',
        'returns': 'tuple',
        'units': None,
        'provider': fpc_get_nodeperm,
        'elements': 2,
    },
    'Power Supply': {
        'type': 'Power Supply',
        'returns': 'tuple',
        'units': None,
        'elements': True,
        'provider': fpc_get_psustatus,
        'elementsfun': get_psu_count,
    },
    'Drip Sensor': {
        'type': 'Management Subsystem Health',
        'elements': True,
        'abselements': 2,
        'returns': 'tuple',
        'units': None,
        'provider': fpc_get_dripstatus,
    }
}


def get_sensor_names(ipmicmd, size):
    global fpc_sensors
    for name in fpc_sensors:
        if size != 6 and name in ('Fan Power', 'Total Power Capacity',
                                  'DC Power'):
            continue
        if size == 6 and name == 'PSU Power Loss':
            continue
        if size != 0x26 and name == 'Drip Sensor':
            continue
        sensor = fpc_sensors[name]

        if 'abselements' in sensor:
            for elemidx in range(sensor['abselements']):
                elemidx += 1
                yield '{0} {1}'.format(name, elemidx)
        elif 'elementsfun' in sensor:
            for elemidx in range(sensor['elementsfun'](ipmicmd, size)):
                elemidx += 1
                yield '{0} {1}'.format(name, elemidx)
        elif 'elements' in sensor:
            for elemidx in range(sensor['elements'] * (size & 0b11111)):
                elemidx += 1
                yield '{0} {1}'.format(name, elemidx)
        else:
            yield name


def get_sensor_descriptions(ipmicmd, size):
    global fpc_sensors
    for name in fpc_sensors:
        if size != 6 and name in ('Fan Power', 'Total Power Capacity',
                                  'DC Power'):
            continue
        if size == 6 and name == 'PSU Power Loss':
            continue
        if size != 0x26 and name == 'Drip Sensor':
            continue
        sensor = fpc_sensors[name]
        if 'abselements' in sensor:
            for elemidx in range(sensor['abselements']):
                elemidx += 1
                yield {'name': '{0} {1}'.format(name, elemidx),
                       'type': sensor['type']}
        elif 'elementsfun' in sensor:
            for elemidx in range(sensor['elementsfun'](ipmicmd, size)):
                elemidx += 1
                yield {'name': '{0} {1}'.format(name, elemidx),
                       'type': sensor['type']}
        elif 'elements' in sensor:
            for elemidx in range(sensor['elements'] * (size & 0b11111)):
                elemidx += 1
                yield {'name': '{0} {1}'.format(name, elemidx),
                       'type': sensor['type']}
        else:
            yield {'name': name, 'type': sensor['type']}


async def get_fpc_firmware(bmcver, ipmicmd, fpcorsmm):
    mymsg = await ipmicmd.raw_command(netfn=0x32, command=0xa8)
    builddata = bytearray(mymsg['data'])
    name = None
    if fpcorsmm != 6:  # SMM
        if fpcorsmm >> 5:
            name = 'SMM2'
            buildid = '{0}{1}{2}{3}{4}{5}{6}'.format(
                *[chr(x) for x in builddata[6:13]])
        else:
            name = 'SMM'
            buildid = '{0}{1}{2}{3}{4}{5}{6}'.format(
                *[chr(x) for x in builddata[5:12]])
    elif len(builddata) == 8:
        builddata = builddata[1:]  # discard the 'completion code'
        name = 'FPC'
        buildid = '{0:02X}{1}'.format(builddata[-2], chr(builddata[-1]))
    bmcmajor, bmcminor = [int(x) for x in bmcver.split('.')]
    bmcver = '{0}.{1:02d}'.format(bmcmajor, bmcminor)
    yield (name, {'version': bmcver, 'build': buildid})
    if fpcorsmm == 6:
        yield ('PSOC', {'version': '{0}.{1}'.format(builddata[2],
                                                    builddata[3])})
    else:
        yield ('PSOC', {'version': '{0}.{1}'.format(builddata[3],
                                                    builddata[4])})


async def get_sensor_reading(name, ipmicmd, sz):
    value = None
    sensor = None
    health = pygconst.Health.Ok
    states = []
    if name in fpc_sensors and 'elements' not in fpc_sensors[name]:
        sensor = fpc_sensors[name]
        value = await sensor['provider'](ipmicmd)
    else:
        bnam, _, idx = name.rpartition(' ')
        idx = int(idx)
        if bnam in fpc_sensors:
            max = -1
            if 'abselements' in fpc_sensors[bnam]:
                max = fpc_sensors[bnam]['abselements']
            elif 'elementsfun' in fpc_sensors[bnam]:
                max = 99
            elif 'elements' in fpc_sensors[bnam]:
                max = fpc_sensors[bnam]['elements'] * sz
            if idx <= max:
                sensor = fpc_sensors[bnam]
                if 'returns' in sensor:
                    health, states = await sensor['provider'](ipmicmd, idx, sz)
                else:
                    value = await sensor['provider'](ipmicmd, idx, sz)
    if sensor is not None:
        return sdr.SensorReading({'name': name, 'imprecision': None,
                                  'value': value, 'states': states,
                                  'state_ids': [], 'health': health,
                                  'type': sensor['type']},
                                 sensor['units'])
    raise Exception('Sensor not found: ' + name)


class SMMClient(object):

    def __init__(self, ipmicmd, variant):
        self.smm_variant = variant
        self.ipmicmd = weakref.proxy(ipmicmd)
        self.smm = ipmicmd.bmc
        self.username = ipmicmd.ipmi_session.userid
        self.password = ipmicmd.ipmi_session.password
        self._wc = None

    async def clear_bmc_configuration(self):
        await self.ipmicmd.raw_command(0x32, 0xad)

    rulemap = {
        'password_reuse_count': 'passwordReuseCheckNum',
        'password_change_interval': 'passwordChangeInterval',
        'password_expiration': 'passwordDurationDays',
        'password_login_failures': 'passwordFailAllowdNum',
        'password_min_length': 'passwordMinLength',
        'password_lockout_period': 'passwordLockoutTimePeriod',
        'timezone': 'timeZone',
    }

    fanmodes = {
        1: 'Capped_20%',
        2: 'Capped_25%',
        3: 'Capped_30%',
        4: 'Capped_45%',
        0: 'Normal',
        5: 'Boosted',
    }

    async def get_bmc_configuration(self, variant):
        settings = {}
        wc = self.wc
        wc.request(
            'POST', '/data',
            ('get=passwordMinLength,passwordForceChange,passwordDurationDays,'
             'passwordExpireWarningDays,passwordChangeInterval,'
             'passwordReuseCheckNum,passwordFailAllowdNum,'
             'passwordLockoutTimePeriod,timeZone'))
        rsp = wc.getresponse()
        rspbody = rsp.read()
        accountinfo = fromstring(rspbody)
        for rule in self.rulemap:
            ruleinfo = accountinfo.find(self.rulemap[rule])
            if ruleinfo is not None:
                try:
                    val = int(ruleinfo.text)
                except ValueError:
                    val = ruleinfo.text
                settings[rule] = {'value': val}
        dwc = await self.ipmicmd.raw_command(0x32, 0x94)
        dwc = bytearray(dwc['data'])
        if len(dwc) not in (3, 4) or dwc[0] == 1:
            rsp = await self.ipmicmd.raw_command(0x34, 3)
            fanmode = self.fanmodes[bytearray(rsp['data'])[0]]
            settings['fanspeed'] = {
                'value': fanmode, 'default': 'Normal',
                'help': ('Adjust the fan speed of the D2 Chassis. Capped '
                         'settings will reduce fan speed for better acoustic '
                         'experience at the expense of performance.  Normal '
                         'is using the Lenovo engineered cooling adjustments '
                         'across the full range. Boosted adds fanspeed to '
                         'the Normal response to provide more aggressive '
                         'cooling.'),
                'possible': [self.fanmodes[x] for x in self.fanmodes]}
        powercfg = await self.ipmicmd.raw_command(0x32, 0xa2)
        powercfg = bytearray(powercfg['data'])
        if len(powercfg) == 5:
            if variant and variant >> 5:
                powercfg = powercfg[-2:]
            else:
                powercfg = powercfg[1:]
        val = powercfg[0]
        if val == 2:
            val = 'N+N'
        elif val == 1:
            val = 'N+1'
        elif val == 0:
            val = 'Disable'
        settings['power_redundancy'] = {
            'default': 'N+1',
            'value': val,
            'possible': ['N+N', 'N+1', 'Disable'],
            'help': ('Configures allowed power budget according to expected '
                     'redundancy. If N+1, power caps will be set to keep '
                     'servers from using more power than the installed power '
                     'supplies could supply if one fails.  If disabled, '
                     'power budget is set to allow nodes to exceed the '
                     'capacity of a single power supply')
        }
        ovs = powercfg[1]
        if ovs == 1:
            ovs = 'Enable'
        elif ovs == 0:
            ovs = 'Disable'
        settings['power_oversubscription'] = {
            'default': 'Enable',
            'value': ovs,
            'possible': ['Enable', 'Disable'],
            'help': ('In redundant power configuration, permit the power '
                     'budget to exceed the capacity of a single power supply '
                     'so long as both power supplies are functioning. This '
                     'excess is limited to an amount that the remaining power '
                     'supply can sustain for a brief period of time in the '
                     'event of losing the other. This excess will be removed '
                     'at the moment a power supply fails so that power '
                     'delivery is at the sustained capacity of the remaining '
                     'supplies.')
        }
        try:
            numbays = 12
            try:
                chassiscapinfo = await self.ipmicmd.raw_command(
                    0x32, 0x9d, data=[13])
            except pygexc.IpmiException as e:
                if e.ipmicode == 201:  # this must be a 2U
                    numbays = 4
                    chassiscapinfo = await self.ipmicmd.raw_command(
                        0x32, 0x9d, data=[5])
                else:
                    raise
            retoffset = 0
            if len(chassiscapinfo['data']) > 10:
                retoffset = 1
            chassiscapstate = await self.ipmicmd.raw_command(
                0x32, 0xa0, data=[numbays + 1])
            capstate = bool(chassiscapstate['data'][retoffset])
            capmin, capmax, protcap, usercap, thermcap = struct.unpack(
                '<HHHHH', chassiscapinfo['data'][retoffset:retoffset + 10])
            settings['chassis_user_cap'] = {
                'value': usercap,
                'help': 'Specify a maximum wattage to consume, this specific '
                        'system implements a range from {0} to {1}.'.format(
                            capmin, capmax)
            }
            settings['chassis_user_cap_active'] = {
                'value': 'Enable' if capstate else 'Disable',
                'help': 'Specify whether the user capping setting should be '
                        'used or not at the chassis level.',
            }
            for baynum in range(numbays):
                baynum += 1
                try:
                    baycapinfo = await self.ipmicmd.raw_command(
                        0x32, 0x9d, data=[baynum])
                except Exception:
                    continue
                capmin, capmax, protcap, usercap, thermcap = struct.unpack(
                    '<HHHHH', baycapinfo['data'][retoffset:retoffset + 10])
                settings['bay{0}_user_cap'.format(baynum)] = {
                    'value': usercap,
                    'help': 'Specify a maximum wattage for the server in bay '
                            '{0} to consume, this specific system implements '
                            'a range from {1} to {2}'.format(
                                baynum, capmin, capmax)
                }
                settings['bay{0}_protective_cap'.format(baynum)] = {
                    'value': protcap,
                    'help': 'Show the current protective cap for the system '
                            'in bay {0}'.format(baynum)
                }
                try:
                    baycapstate = await self.ipmicmd.raw_command(
                        0x32, 0xa0, data=[baynum])
                except Exception:
                    continue
                baycapstate = bool(baycapstate['data'][retoffset])
                settings['bay{0}_user_cap_active'.format(baynum)] = {
                    'value': 'Enable' if baycapstate else 'Disable',
                    'help': 'Specify whether the user capping setting should '
                            'be used or not for bay {0}'.format(baynum),
                    'possible': ['Enable', 'Disable'],
                }
        except Exception:
            pass
        try:
            dhcpsendname = await self.ipmicmd.raw_command(0xc, 0x2,
                                                     data=[1, 0xc5, 0, 0])
            dhcpsendname = bytearray(dhcpsendname['data'])
            dhcpsendname = 'Enable' if dhcpsendname[1] == 1 else 'Disable'
            settings['dhcp_sends_hostname'] = {
                'value': dhcpsendname,
                'help': ('Have the device send  hostname as part of its '
                         'DHCP client requests in option 12'),
                'possible': ['Enable', 'Disable']
            }
            dhcpsendvci = await self.ipmicmd.raw_command(0xc, 0x2,
                                                    data=[1, 0xc6, 0, 0])
            dhcpsendvci = bytearray(dhcpsendvci['data'])
            dhcpsendvci = 'Enable' if dhcpsendvci[1] == 1 else 'Disable'
            settings['dhcp_sends_vendor_class_identifier'] = {
                'value': dhcpsendvci,
                'possible': ['Enable', 'Disable'],
                'help': ('Have the device send vendor class identifier '
                         'as part of its DHCP requests in option 60')
            }
        except Exception:
            pass
        try:
            chassisvpd = await self.ipmicmd.raw_command(0x32, 0xb0, data=(5, 0))
            chassisvpd = bytearray(chassisvpd['data'][2:])
            chassisvpd = bytes(chassisvpd).strip()
            if not isinstance(chassisvpd, str):
                chassisvpd = chassisvpd.decode('utf8')
            settings['chassis_model'] = {
                'value': chassisvpd,
                'help': ('Configure the chassis model number')
            }
        except Exception:
            pass
        try:
            chassisvpd = await self.ipmicmd.raw_command(0x32, 0xb0, data=(5, 1))
            chassisvpd = bytearray(chassisvpd['data'][2:])
            chassisvpd = bytes(chassisvpd).strip()
            if not isinstance(chassisvpd, str):
                chassisvpd = chassisvpd.decode('utf8')
            settings['chassis_serial'] = {
                'value': chassisvpd,
                'help': ('Configure the chassis serial number')
            }
        except Exception:
            pass
        return settings

    async def set_bay_cap(self, baynum, val):
        payload = struct.pack('<BH', baynum, int(val))
        await self.ipmicmd.raw_command(0x32, 0x9e, data=payload)

    async def augment_zerofru(self, zerofru, variant):
        if variant & 0x20 != 0x20:
            return
        model = (await self.ipmicmd.raw_command(
            netfn=0x32, command=0xb0, data=[5, 11]))['data'][2:]
        zerofru['Product name'] = bytes(model).strip()
        zerofru['Manufacturer'] = 'Lenovo'

    async def set_bay_cap_active(self, baynum, val):
        currstate = await self.ipmicmd.raw_command(0x32, 0xa0, data=[baynum])
        currstate = currstate['data']
        if len(currstate) == 5:
            currstate = currstate[1:]
        savemode = currstate[3]
        enable = val.lower().startswith('enable')
        payload = [baynum, 1 if enable else 0, savemode]
        await self.ipmicmd.raw_command(0x32, 0x9f, data=payload)

    async def set_bmc_configuration(self, changeset, variant):
        rules = []
        powercfg = [None, None]
        sendhost = None
        sendvci = None
        newserial = None
        newmodel = None
        for key in changeset:
            if not key:
                raise pygexc.InvalidParameterValue('Empty key is invalid')
            if isinstance(changeset[key], str):
                changeset[key] = {'value': changeset[key]}
            for rule in self.rulemap:
                if fnmatch.fnmatch(rule, key.lower()):
                    rules.append('{0}:{1}'.format(
                        self.rulemap[rule], changeset[key]['value']))
            if fnmatch.fnmatch('power_redundancy', key.lower()):
                if 'n+n'.startswith(changeset[key]['value'].lower()):
                    powercfg[0] = 2
                elif 'n+1'.startswith(changeset[key]['value'].lower()):
                    powercfg[0] = 1
                elif 'disable'.startswith(changeset[key]['value'].lower()):
                    powercfg[0] = 0
            if fnmatch.fnmatch('power_oversubscription', key.lower()):
                ovs = changeset[key]['value']
                ovs = stringtoboolean(changeset[key]['value'],
                                      'power_oversubscription')
                powercfg[1] = 1 if ovs else 0
            if fnmatch.fnmatch('dhcp_sends_hostname', key.lower()):
                sendhost = changeset[key]['value']
                sendhost = stringtoboolean(changeset[key]['value'],
                                           'dhcp_sends_hostname')
            if fnmatch.fnmatch(
                    'dhcp_sends_vendor_class_identifier', key.lower()):
                sendvci = changeset[key]['value']
                sendvci = stringtoboolean(
                    changeset[key]['value'],
                    'dhcp_sends_vendor_class_identifier')
            if fnmatch.fnmatch('chassis_serial', key.lower()):
                newserial = changeset[key]['value']
            if fnmatch.fnmatch('chassis_model', key.lower()):
                newmodel = changeset[key]['value']
            # Variant low 8 bits is the height in U of chassis, so double that
            #  to get maxbays
            numbays = (self.smm_variant & 0x0f) << 1
            for bayn in range(1, numbays + 1):
                if fnmatch.fnmatch('bay{0}_user_cap'.format(bayn),
                                   key.lower()):
                    self.set_bay_cap(bayn, changeset[key]['value'])
                if fnmatch.fnmatch(
                        'bay{0}_user_cap_active'.format(bayn), key.lower()):
                    self.set_bay_cap_active(bayn, changeset[key]['value'])
            if fnmatch.fnmatch('chassis_user_cap', key.lower()):
                self.set_bay_cap(numbays + 1, changeset[key]['value'])
            if fnmatch.fnmatch('chassis_user_cap_active', key.lower()):
                self.set_bay_cap_active(numbays + 1, changeset[key]['value'])
            if fnmatch.fnmatch('fanspeed', key.lower()):
                for mode in self.fanmodes:
                    byteval = mode
                    mode = self.fanmodes[mode]
                    if changeset[key]['value'].lower() == mode.lower():
                        await self.ipmicmd.raw_command(
                            0x32, 0x9b, data=[byteval])
                        break
                else:
                    raise pygexc.InvalidParameterValue(
                        '{0} not a valid mode for fanspeed'.format(
                            changeset[key]['value']))
        if rules:
            rules = 'set={0}'.format(','.join(rules))
            wc = self.wc
            wc.request('POST', '/data', rules)
            wc.getresponse().read()
        if powercfg != [None, None]:
            if variant != 6:
                if None in powercfg:
                    currcfg = await self.ipmicmd.raw_command(0x32, 0xa2)
                    currcfg = bytearray(currcfg['data'])
                    if variant and variant >> 5 and len(currcfg) == 5:
                        currcfg = currcfg[-2:]
                    if powercfg[0] is None:
                        powercfg[0] = currcfg[0]
                    if powercfg[1] is None:
                        powercfg[1] = currcfg[1]
                await self.ipmicmd.raw_command(0x32, 0xa3, data=powercfg)
            elif variant == 6:
                if powercfg[0] is not None:
                    await self.ipmicmd.raw_command(0x32, 0xa3, data=powercfg[:1])
                if powercfg[1] is not None:
                    await self.ipmicmd.raw_command(0x32, 0x9c, data=powercfg[1:])
        if sendhost is not None:
            sendhost = 1 if sendhost else 0
            await self.ipmicmd.raw_command(0xc, 1, data=[1, 0xc5, sendhost])
        if sendvci is not None:
            sendvci = 1 if sendvci else 0
            await self.ipmicmd.raw_command(0xc, 1, data=[1, 0xc6, sendvci])
        if newserial:
            newserial = newserial.ljust(10).encode('utf8')
            cmdata = b'\x05\x01' + newserial
            await self.ipmicmd.raw_command(0x32, 0xaf, data=cmdata)
        if newmodel:
            newmodel = newmodel.ljust(10).encode('utf8')
            cmdata = b'\x05\x00' + newmodel
            await self.ipmicmd.raw_command(0x32, 0xaf, data=cmdata)

    async def set_user_priv(self, uid, priv):
        if priv.lower() == 'administrator':
            rsp = await self.ipmicmd.raw_command(netfn=6, command=0x46, data=(uid,))
            username = bytes(rsp['data']).rstrip(b'\x00')
            if not isinstance(username, str):
                username = username.decode('utf8')
            wc = self.wc
            wc.request(
                'POST', '/data', 'set=user({0},1,{1},511,,4,15,0)'.format(
                    uid, username))
            rsp = wc.getresponse()
            rsp.read()

    async def reseat_bay(self, bay):
        bay = int(bay)
        if bay == -1:
            await self.ipmicmd.raw_command(0x32, 0xf5)
            return
        if bay % 2 == 0:
            # even node may be unable to reseat based on shared io
            try:
                rsp = await self.ipmicmd.raw_command(0x32, 0xc5, data=[1])
            except Exception:
                rsp = {'data': [1]}
            rsp['data'] = bytearray(rsp['data'])
            if rsp['data'][0] == 2:  # shared io
                try:
                    rsp = await self.ipmicmd.raw_command(0x32, 0xa7, data=[bay - 1])
                except Exception:
                    raise Exception('Shared IO detected trying to reseat {}, '
                                    'but unable to determine status of '
                                    'partner bay {}'.format(
                                        bay, bay - 1))               
                rsp['data'] = bytearray(rsp['data'])
                if rsp['data'][1] == 0x80:
                    raise Exception('Unable to reseat bay {0} due to bay {1} '
                                    'being on with shared IO'.format(
                                        bay, bay - 1))
        await self.ipmicmd.raw_command(netfn=0x32, command=0xa4,
                                  data=[bay, 2])

    async def get_diagnostic_data(self, savefile, progress=None, autosuffix=False,
                            variant=None):
        if variant == 6:
            raise Exception('Service data not supported on FPC')
        rsp = await self.ipmicmd.raw_command(netfn=0x32, command=0xb1, data=[0])
        if bytearray(rsp['data'])[0] != 0:
            raise Exception("Service data generation already in progress")
        rsp = await self.ipmicmd.raw_command(netfn=0x34, command=0x12, data=[0])
        if bytearray(rsp['data'])[0] != 0:
            raise Exception("Service data generation already in progress")
        rsp['data'] = b'\x01'
        initpct = 1.0
        if progress:
            progress({'phase': 'initializing', 'progress': initpct})
        while bytearray(rsp['data'])[0] != 0:
            ipmisession.Session.pause(3)
            initpct += 3.0
            if initpct > 99.0:
                initpct = 99.0
            rsp = await self.ipmicmd.raw_command(netfn=0x34, command=0x12, data=[1])
            if progress:
                progress({'phase': 'initializing', 'progress': initpct})
        wc = self.wc
        if wc is None:
            raise Exception("Failed to connect to web api")
        if variant and variant >> 5:
            url = '/preview/smm2-ffdc.tgz?ST1={0}'.format(wc.st1)
        else:
            url = '/preview/smm-ffdc.tgz?ST1={0}'.format(wc.st1)
        if autosuffix and not savefile.endswith('.tgz'):
            savefile += '-smm-ffdc.tgz'
        fd = webclient.make_downloader(wc, url, savefile)
        while not fd.completed():
            try:
                await fd.join(1)
            except asyncio.TimeoutError:
                pass
            if progress and await fd.get_progress():
                progress({'phase': 'download',
                          'progress': 100 * await fd.get_progress()})
        if progress:
            progress({'phase': 'complete'})
        return savefile

    async def process_fru(self, fru):
        smmv1 = self.smm_variant & 0xf0 == 0
        # TODO(jjohnson2): can also get EIOM, SMM, and riser data if warranted
        snum = bytes(await self.ipmicmd.raw_command(
            netfn=0x32, command=0xb0, data=(5, 1))['data'][:])
        mnum = bytes(await self.ipmicmd.raw_command(
            netfn=0x32, command=0xb0, data=(5, 0))['data'][:])
        if not smmv1:
            snum = snum[2:]
            mnum = mnum[2:]
        fru['Serial Number'] = snum.strip(b' \x00\xff').replace(b'\xff', b'')
        fru['Model'] = mnum.strip(b' \x00\xff').replace(b'\xff', b'')
        return fru

    def get_webclient(self):
        cv = self.ipmicmd.certverify
        wc = webclient.SecureHTTPConnection(self.smm, 443, verifycallback=cv)
        wc = webclient.WebConnection(self.smm, 443, verifycallback=cv)
        wc.vintage = util._monotonic_time()
        wc.connect()
        loginform = urlencode(
            {
                'user': self.username,
                'password': self.password
            }
        )
        wc.request('POST', '/data/login', loginform)
        rsp = wc.getresponse()
        if rsp.status != 200:
            raise Exception(rsp.read())
        authdata = rsp.read()
        authdata = fromstring(authdata)
        for data in authdata.findall('authResult'):
            if int(data.text) != 0:
                raise Exception("Firmware update already in progress")
        for data in authdata.findall('forwardUrl'):
            if 'renew' in data.text:
                raise Exception("Account password has expired on remote "
                                "device")
        wc.st1 = None
        wc.st2 = None
        for data in authdata.findall('st1'):
            wc.st1 = data.text
        for data in authdata.findall('st2'):
            wc.st2 = data.text
        if not wc.st2:
            # This firmware puts tokens in the html file, parse that
            wc.request('GET', '/index.html')
            rsp = wc.getresponse()
            if rsp.status != 200:
                raise Exception(rsp.read())
            indexhtml = rsp.read()
            if not isinstance(indexhtml, str):
                indexhtml = indexhtml.decode('utf8')
            for line in indexhtml.split('\n'):
                if '"ST1"' in line:
                    wc.st1 = line.split()[-1].replace(
                        '"', '').replace(',', '')
                if '"ST2"' in line:
                    wc.st2 = line.split()[-1].replace(
                        '"', '').replace(',', '')
        if not wc.st2:
            wc.request('GET', '/scripts/index.ajs')
            rsp = wc.getresponse()
            body = rsp.read()
            if rsp.status != 200:
                raise Exception(body)
            if not isinstance(body, str):
                body = body.decode('utf8')
            for line in body.split('\n'):
                if '"ST1"' in line:
                    wc.st1 = line.split()[-1].replace(
                        '"', '').replace(',', '')
                if '"ST2"' in line:
                    wc.st2 = line.split()[-1].replace(
                        '"', '').replace(',', '')
        if not wc.st2:
            raise Exception('Unable to locate ST2 token')
        wc.set_header('ST2', wc.st2)
        return wc

    def set_hostname(self, hostname):
        wc = self.wc
        wc.request('POST', '/data', 'set=hostname:' + hostname)
        rsp = wc.getresponse()
        if rsp.status != 200:
            raise Exception(rsp.read())
        rsp.read()
        self.logout()

    def get_hostname(self):
        currinfo = self.get_netinfo()
        self.logout()
        for data in currinfo.find('netConfig').findall('hostname'):
            return data.text

    def get_netinfo(self):
        wc = self.wc
        wc.request('POST', '/data', 'get=hostname')
        rsp = wc.getresponse()
        data = rsp.read()
        if rsp.status == 400:
            wc.request('POST', '/data?get=hostname', '')
            rsp = wc.getresponse()
            data = rsp.read()
        if rsp.status != 200:
            raise Exception(data)
        currinfo = fromstring(data)
        return currinfo

    def set_domain(self, domain):
        wc = self.wc
        wc.request('POST', '/data', 'set=dnsDomain:' + domain)
        rsp = wc.getresponse()
        if rsp.status != 200:
            raise Exception(rsp.read())
        rsp.read()
        self.logout()

    def get_domain(self):
        currinfo = self.get_netinfo()
        self.logout()
        for data in currinfo.find('netConfig').findall('dnsDomain'):
            return data.text

    def get_ntp_enabled(self, variant):
        wc = self.wc
        wc.request('POST', '/data', 'get=ntpOpMode')
        rsp = wc.getresponse()
        info = fromstring(rsp.read())
        self.logout()
        for data in info.findall('ntpOpMode'):
            return data.text == '1'

    def set_ntp_enabled(self, enabled):
        wc = self.wc
        wc.request('POST', '/data', 'set=ntpOpMode:{0}'.format(
            1 if enabled else 0))
        rsp = wc.getresponse()
        result = rsp.read()
        if not isinstance(result, str):
            result = result.decode('utf8')
        self.logout()
        if '<status>ok</status>' not in result:
            raise Exception("Unrecognized result: " + result)

    def set_ntp_server(self, server, index):
        wc = self.wc
        wc.request('POST', '/data', 'set=ntpServer{0}:{1}'.format(
            index + 1, server))
        rsp = wc.getresponse()
        result = rsp.read()
        if not isinstance(result, str):
            result = result.decode('utf8')
        if '<status>ok</status>' not in result:
            raise Exception("Unrecognized result: " + result)
        self.logout()
        return True

    def get_ntp_servers(self):
        wc = self.wc
        wc.request(
            'POST', '/data', 'get=ntpServer1,ntpServer2,ntpServer3')
        rsp = wc.getresponse()
        result = fromstring(rsp.read())
        srvs = []
        for data in result.findall('ntpServer1'):
            srvs.append(data.text)
        for data in result.findall('ntpServer2'):
            srvs.append(data.text)
        for data in result.findall('ntpServer3'):
            srvs.append(data.text)
        self.logout()
        return srvs

    async def update_firmware(self, filename, data=None, progress=None, bank=None):
        if progress is None:
            def progress(x):
                return True
        z = None
        if data and hasattr(data, 'read'):
            if zipfile.is_zipfile(data):
                z = zipfile.ZipFile(data)
            else:
                data.seek(0)
        elif data is None and zipfile.is_zipfile(filename):
            z = zipfile.ZipFile(filename)
        if z:
            for tmpname in z.namelist():
                if tmpname.endswith('.rom'):
                    filename = tmpname
                    data = z.open(filename)
                    break
        progress({'phase': 'upload', 'progress': 0.0})
        wc = self.wc
        wc.request('POST', '/data', 'set=fwType:10')  # SMM firmware
        rsp = wc.getresponse()
        rsp.read()
        url = '/fwupload/fwupload.esp?ST1={0}'.format(wc.st1)
        fu = await webclient.make_uploader(
            wc, url, filename, data, formname='fileUpload',
            otherfields={'preConfig': 'on'})
        while not fu.completed():
            try:
                await fu.join(3)
            except asyncio.TimeoutError:
                pass
            if progress:
                progress({'phase': 'upload',
                          'progress': 100 * await fu.get_progress()})
        progress({'phase': 'validating', 'progress': 0.0})
        url = '/data'
        wc.request('POST', url, 'get=fwVersion,spfwInfo')
        rsp = wc.getresponse()
        rsp.read()
        if rsp.status != 200:
            raise Exception('Error validating firmware')
        progress({'phase': 'apply', 'progress': 0.0})
        wc.request('POST', '/data', 'set=securityrollback:1')
        wc.getresponse().read()
        wc.request('POST', '/data', 'set=fwUpdate:1')
        rsp = wc.getresponse()
        rsp.read()
        complete = False
        tries = 0
        while not complete:
            ipmisession.Session.pause(3)
            wc.request('POST', '/data', 'get=fwProgress,fwUpdate')
            try:
                rsp = wc.getresponse()
                progdata = rsp.read()
            except Exception:
                if tries > 2:
                     break
                tries += 1
                continue
            if rsp.status != 200:
                raise Exception('Error applying firmware')
            progdata = fromstring(progdata)
            if progdata.findall('fwUpdate')[0].text == 'invalid signature':
                raise Exception('Firmware signature invalid')
            percent = float(progdata.findall('fwProgress')[0].text)

            progress({'phase': 'apply',
                      'progress': percent})
            complete = percent >= 100.0
        return 'complete'

    def get_inventory_descriptions(self, ipmicmd, variant):
        if variant >> 5 == 0:
            return
        psucount = get_psu_count(ipmicmd, variant)
        for idx in range(psucount):
            yield 'PSU {}'.format(idx + 1)

    def get_inventory_of_component(self, ipmicmd, component):
        psuidx = int(component.replace('PSU ', ''))
        return self.get_psu_info(ipmicmd, psuidx)

    async def get_psu_info(self, ipmicmd, psunum):
        psuinfo = await ipmicmd.raw_command(0x34, 0x6, data=(psunum,))
        psuinfo = bytearray(psuinfo['data'])
        psutype = struct.unpack('<H', psuinfo[23:25])[0]
        psui = {}
        if psuinfo[0] != 1:
            return {'Model': 'Unavailable'}
        psui['Revision'] = psuinfo[34]
        psui['Description'] = psutypes.get(
            psutype, 'Unknown ({})'.format(psutype))
        psui['Part Number'] = str(psuinfo[35:47].strip(
            b' \x00\xff').decode('utf8'))
        psui['FRU Number'] = str(psuinfo[47:59].strip(
            b' \x00\xff').decode('utf8'))
        psui['Serial Number'] = str(psuinfo[59:71].strip(
            b' \x00\xff').decode('utf8'))
        psui['Header Code'] = str(psuinfo[71:75].strip(
            b' \x00\xff').decode('utf8'))
        psui['Vendor'] = str(psuinfo[25:29].strip(
            b' \x00\xff').decode('utf8'))
        psui['Manufacturing Date'] = '20{}-W{}'.format(
            psuinfo[77:79].decode('utf8'), psuinfo[75:77].decode('utf8'))
        psui['Primary Firmware Version'] = '{:x}.{:x}'.format(
            psuinfo[80], psuinfo[79])
        psui['Secondary Firmware Version'] = '{:x}.{:x}'.format(
            psuinfo[82], psuinfo[81])
        psui['Model'] = str(psuinfo[5:23].strip(b' \x00\xff').decode('utf8'))
        psui['Manufacturer Location'] = str(
            psuinfo[83:85].strip(b' \x00\xff').decode('utf8'))
        psui['Barcode'] = str(psuinfo[85:108].strip(
            b' \x00\xff').decode('utf8'))
        return psui

    def logout(self):
        wc = self.wc
        wc.request('POST', '/data/logout', None)
        rsp = wc.getresponse()
        rsp.read()
        self._wc = None

    async def wc(self):
        if (not self._wc or self._wc.broken
                or self._wc.vintage < util._monotonic_time() + 30):
            self._wc = await self.get_webclient()
        return self._wc
