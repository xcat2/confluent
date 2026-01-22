# Copyright 2022 Lenovo
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

from xml.etree.ElementTree import fromstring as rfromstring
import confluent.util as util
import confluent.messages as msg
import confluent.exceptions as exc
import confluent.tasks as tasks
import aiohmi.util.webclient as wc
import time

sensorsbymodel = {
    'FS1350': ['alarms', 'dt', 'duty', 'dw', 'mode', 'p3state', 'primflow', 'ps1', 'ps1a', 'ps1b', 'ps2', 'ps3', 'ps4', 'ps5a', 'ps5b', 'ps5c', 'pumpspeed1', 'pumpspeed2', 'pumpspeed3', 'rh', 'sdp', 'secflow', 'setpoint', 't1', 't2', 't2a', 't2b', 't2c', 't3', 't3', 't4', 't5', 'valve', 'valve2'],
    'FS600': ['alarms', 'dt', 'duty', 'dw', 'mode', 'p3state', 'pdp', 'primflow', 'ps1', 'ps1a', 'ps1b', 'ps2', 'ps3', 'ps4', 'ps5a', 'ps5b', 'pumpspeed1', 'pumpspeed2', 'rh', 'sdp', 'secflow', 'setpoint', 't1', 't2', 't2a', 't2b', 't2c', 't3', 't3', 't4', 't5', 'valve'],
    'RM100': ['alarms', 'dt', 'duty', 'dw', 'mode', 'p3state', 'primflow', 'ps1', 'ps1a', 'ps2', 'ps3', 'pumpspeed1', 'pumpspeed2', 'rh', 'sdp', 'secflow', 'setpoint', 't1', 't2', 't2a', 't2b', 't2c', 't3', 't3', 't4', 't5', 'valve'],
}
_thesensors = {
    'RM100': {
        't1': ('Primary loop supply temperature', 'degC'),
        't2': ('Secondary loop supply temperature', 'degC'),
        't4': ('Secondary loop return temperature', 'degC'),
        't3': ('Ambient air temperature', 'degC'),
        't5': ('Primary loop return temperature', 'degC'),
        'rh': ('Relative Humidity', '%'),
        'dw': ('Dewpoint', 'degC'),
        'pumpspeed1': ('Pump 1 Speed', '%'),
        'pumpspeed2': ('Pump 2 Speed', '%'),
        'alarms': ('Number of active alarms', ''),
        'primflow': ('Input flow rate', 'l/m'),
        'secflow': ('Output flow rate', 'l/m'),
        'ps1': ('Secondary loop return pressure', 'bar'),
        'ps3': ('Secondary loop supply pressure', 'bar'),
    },
    'FS600': {
        't1': ('Primary loop supply temperature', 'degC'),
        't2': ('Secondary loop supply temperature', 'degC'),
        't4': ('Secondary loop return temperature', 'degC'),
        't5': ('Primary loop return temperature', 'degC'),
        't3': ('Ambient air temperature', 'degC'),
        'rh': ('Relative Humidity', '%'),
        'dw': ('Dewpoint', 'degC'),
        'pumpspeed1': ('Pump 1 Speed', '%'),
        'pumpspeed2': ('Pump 2 Speed', '%'),
        'alarms': ('Number of active alarms', ''),
        'primflow': ('Input flow rate', 'l/m'),
        'secflow': ('Output flow rate', 'l/m'),
        'ps1': ('Secondary loop return pressure', 'bar'),
        'ps3': ('Primary loop supply pressure', 'bar'),
        'ps2': ('Secondary loop supply pressure', 'bar'),
    },
    'FS1350': {
        't1': ('Primary loop supply temperature', 'degC'),
        't2': ('Secondary loop supply temperature', 'degC'),
        't4': ('Secondary loop return temperature', 'degC'),
        't5': ('Primary loop return temperature', 'degC'),
        't3': ('Ambient air temperature', 'degC'),
        'rh': ('Relative Humidity', '%'),
        'dw': ('Dewpoint', 'degC'),
        'pumpspeed1': ('Pump 1 Speed', '%'),
        'pumpspeed2': ('Pump 2 Speed', '%'),
        'pumpspeed3': ('Pump 2 Speed', '%'),
        'alarms': ('Number of active alarms', ''),
        'primflow': ('Input flow rate', 'l/m'),
        'secflow': ('Output flow rate', 'l/m'),
        'ps1': ('Secondary loop return pressure', 'bar'),
        'ps3': ('Primary loop supply pressure', 'bar'),
        'ps2': ('Secondary loop supply pressure', 'bar'),
        'ps4': ('Primary loop return pressure', 'bar'),
    },
}


def fromstring(inputdata):
    if isinstance(inputdata, bytes):
        cmpstr = b'!entity'
    else:
        cmpstr = '!entity'
    if cmpstr in inputdata.lower():
        raise Exception('!ENTITY not supported in this interface')
    # The measures above should filter out the risky facets of xml
    # We don't need sophisticated feature support
    return rfromstring(inputdata)  # nosec

def simplify_name(name):
    return name.lower().replace(' ', '_').replace('/', '-').replace(
        '_-_', '-')

class CoolteraClient(object):
    def __init__(self, cdu, configmanager):
        self.node = cdu
        self.configmanager = configmanager
        self._wc = None

    @property
    def wc(self):
        if self._wc:
            return self._wc
        targcfg = self.configmanager.get_node_attributes(self.node,
                                            ['hardwaremanagement.manager'],
                                            decrypt=True)
        targcfg = targcfg.get(self.node, {})
        target = targcfg.get(
            'hardwaremanagement.manager', {}).get('value', None)
        if not target:
            target = self.node
        target = target.split('/', 1)[0]
        cv = util.TLSCertVerifier(
            self.configmanager, self.node,
            'pubkeys.tls_hardwaremanager').verify_cert
        self._wc = wc.WebConnection(target, 443, verifycallback=cv)
        return self._wc

    
def xml2stateinfo(statdata):
    statdata = fromstring(statdata)
    stateinfo = []
    sensornames = sorted([x.tag for x in statdata])
    themodel = None
    for model in sorted(sensorsbymodel):
        if all([x in sensornames for x in sensorsbymodel[model]]):
            themodel = model
            break
    else:
        print(repr(sensornames))
    thesensors = _thesensors[themodel]
#['mode', 't1', 't2a', 't2b', 't2c', 't2', 't5', 't3', 't4', 'dw', 't3', 'rh', 'setpoint', 'secflow', 'primflow', 'ps1', 'ps1a', 'ps1b', 'ps2', 'ps3', 'ps4', 'ps5a', 'ps5b', 'ps5c', 'sdp', 'valve', 'valve2', 'pumpspeed1', 'pumpspeed2', 'pumpspeed3', 'alarms', 'dt', 'p3state', 'duty']
    for tagname in thesensors:
        label, units = thesensors[tagname]
        val = statdata.find(tagname).text.replace(units, '').strip()
        stateinfo.append({
            'name': label,
            'value': val,
            'units': units.replace('degC', '°C'),
            'type': 'Temperature',
        })
    return stateinfo

    
_sensors_by_node = {}
async def read_sensors(element, node, configmanager):
    category, name = element[-2:]
    if len(element) == 3:
        # just get names
        category = name
        name = 'all'
        for sensor in sensors:
            yield msg.ChildCollection(simplify_name(sensors[sensor][0]))
        return     
    if category in ('leds, fans'):
        return
    sn = _sensors_by_node.get(node, None)
    if not sn or sn[1] < time.time():
        cc = CoolteraClient(node, configmanager)
        statdata, status, hdrs = await cc.wc.grab_response_with_status('/status.xml')
        statinfo = xml2stateinfo(statdata)
        _sensors_by_node[node] = (statinfo, time.time() + 1)
        sn = _sensors_by_node.get(node, None)
    if sn:
        yield msg.SensorReadings(sn[0], name=node)


async def retrieve(nodes, element, configmanager, inputdata):
    if element[0] == 'sensors':
        taskargs = []
        for node in nodes:
            taskargs.append((element, node, configmanager))
        gp = tasks.starmap(read_sensors, taskargs)
        async for rsp in gp:
            for datum in rsp:
                yield datum
        return
