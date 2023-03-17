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

import pyghmi.util.webclient as wc
import confluent.util as util
import confluent.messages as msg
import confluent.exceptions as exc
import eventlet.green.time as time
import eventlet.greenpool as greenpool

def simplify_name(name):
    return name.lower().replace(' ', '_').replace('/', '-').replace(
        '_-_', '-')

pdupool = greenpool.GreenPool(128)

class GeistClient(object):
    def __init__(self, pdu, configmanager):
        self.node = pdu
        self.configmanager = configmanager
        self._token = None
        self._wc = None
        self.username = None

    @property
    def token(self):
        if not self._token:
            self._token = self.login(self.configmanager)
        return self._token

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
        self._wc = wc.SecureHTTPConnection(target, port=443, verifycallback=cv)
        return self._wc

    def login(self, configmanager):
        credcfg = configmanager.get_node_attributes(self.node,
                                            ['secret.hardwaremanagementuser',
                                             'secret.hardwaremanagementpassword'],
                                            decrypt=True)
        credcfg = credcfg.get(self.node, {})
        username = credcfg.get(
            'secret.hardwaremanagementuser', {}).get('value', None)
        passwd = credcfg.get(
            'secret.hardwaremanagementpassword', {}).get('value', None)
        if not isinstance(username, str):
            username = username.decode('utf8')
        if not isinstance(passwd, str):
            passwd = passwd.decode('utf8')
        if not username or not passwd:
            raise Exception('Missing username or password')
        self.username = username
        rsp = self.wc.grab_json_response(
            '/api/auth/{0}'.format(username),
            {'cmd': 'login', 'data': {'password': passwd}})
        token = rsp['data']['token']
        return token

    def logout(self):
        if self._token:
            self.wc.grab_json_response('/api/auth/{0}'.format(self.username),
                                       {'cmd': 'logout', 'token': self.token})
            self._token = None

    def get_outlet(self, outlet):
        rsp = self.wc.grab_json_response('/api/dev')
        rsp = rsp['data']
        if len(rsp) != 1:
            raise Exception('Multiple PDUs not supported per pdu')
        pduname = list(rsp)[0]
        outlet = rsp[pduname]['outlet'][str(int(outlet) - 1)]
        state = outlet['state'].split('2')[-1]
        return state

    def set_outlet(self, outlet, state):
        rsp = self.wc.grab_json_response('/api/dev')
        if len(rsp['data']) != 1:
            self.logout()
            raise Exception('Multiple PDUs per endpoint not supported')
        pdu = list(rsp['data'])[0]
        outlet = int(outlet) - 1
        rsp = self.wc.grab_json_response(
            '/api/dev/{0}/outlet/{1}'.format(pdu, outlet),
            {'cmd': 'control', 'token': self.token,
            'data': {'action': state, 'delay': False}})

_sensors_by_node = {}
def read_sensors(element, node, configmanager):
    category, name = element[-2:]
    justnames = False
    if len(element) == 3:
        # just get names
        category = name
        justnames = True
    if category in ('leds, fans', 'temperature'):
        return
    sn = _sensors_by_node.get(node, None)
    if not sn or sn[1] < time.time():
        gc = GeistClient(node, configmanager)
        adev = gc.wc.grab_json_response('/api/dev')
        _sensors_by_node[node] = (adev, time.time() + 1)
        sn = _sensors_by_node.get(node, None)
    if len(sn[0]['data']) != 1:
        raise Exception('Unable to support multiple pdus at an ip')
    print(repr(element))
    readings = []
    totalenergy = 0.0
    totalrealpower = 0.0
    totalapparentpower = 0.0
    for pduid in sn[0]['data']:
        datum = sn[0]['data'][pduid]
        for ent in util.natural_sort(list(datum['entity'])):
            outsensors = datum['entity'][ent]['measurement']
            if ent.startswith('breaker'):
                continue
            if ent == 'total0':
                continue
        for outlet in util.natural_sort(list(datum['outlet'])):
            outsensors = datum['outlet'][outlet]['measurement']
            for measure in outsensors:
                measurement = outsensors[measure]
                if measurement['type'] == 'energy' and category != 'power':
                    myname = 'Outlet {0} Energy'.format(int(outlet) + 1)
                    if justnames:
                        yield msg.ChildCollection(simplify_name(myname))
                        continue
                    totalenergy += float(measurement['value'])
                    if name != 'all' and simplify_name(myname) != name:
                        continue
                    reading = {
                        'name': myname,
                        'value': float(measurement['value']),
                        'units': measurement['units'],
                        'type': 'Energy'
                    }
                    readings.append(reading)
                if measurement['type'] == 'realPower' and category != 'energy':
                    myname = 'Outlet {0} Real Power'.format(int(outlet) + 1)
                    if justnames:
                        yield msg.ChildCollection(simplify_name(myname))
                        continue
                    totalrealpower += float(measurement['value'])
                    if name != 'all' and simplify_name(myname) != name:
                        continue
                    reading = {
                        'name': myname,
                        'value': float(measurement['value']),
                        'units': measurement['units'],
                        'type': 'Current'
                    }
                    readings.append(reading)
                if measurement['type'] == 'voltage' and category == 'all':
                    myname = 'Outlet {0} Voltage'.format(int(outlet) + 1)
                    if justnames:
                        yield msg.ChildCollection(simplify_name(myname))
                        continue
                    if name != 'all' and simplify_name(myname) != name:
                        continue
                    reading = {
                        'name': myname,
                        'value': float(measurement['value']),
                        'units': measurement['units'],
                        'type': 'Voltage'
                    }
                    readings.append(reading)
                if measurement['type'] == 'apparentPower' and category != 'energy':
                    myname = 'Outlet {0} Apparent Power'.format(int(outlet) + 1)
                    if justnames:
                        yield msg.ChildCollection(simplify_name(myname))
                        continue
                    totalapparentpower += float(measurement['value'])
                    if name != 'all' and simplify_name(myname) != name:
                        continue
                    reading = {
                        'name': myname,
                        'value': float(measurement['value']),
                        'units': measurement['units'],
                        'type': 'Current'
                    }
                    readings.append(reading)
    myname = 'Overall Energy'
    if justnames and category != 'power':
        yield msg.ChildCollection(simplify_name(myname))
    elif (name == 'all' or simplify_name(myname) == name) and category != 'power':
        readings.append({
            'name': 'Overall Energy',
            'value': totalenergy,
            'units': 'kWh',
            'type': 'Energy',
        })
    myname = 'Overall Real Power'
    if justnames and category != 'energy':
        yield msg.ChildCollection(simplify_name(myname))
    elif (name == 'all' or simplify_name(myname) == name) and category != 'energy':
        readings.append({
            'name': 'Overall Real Power',
            'value': totalrealpower,
            'units': 'W',
            'type': 'Current',
        })
    myname = 'Overall Apparent Power'
    if justnames and category != 'energy':
        yield msg.ChildCollection(simplify_name(myname))
    elif (name == 'all' or simplify_name(myname) == name) and category != 'energy':
        readings.append({
            'name': 'Overall Apparent Power',
            'value': totalapparentpower,
            'units': 'VA',
            'type': 'Current',
        })
    if readings:
        yield msg.SensorReadings(readings, name=node)

def get_outlet(node, configmanager):
    gc = GeistClient(node, configmanager)
    state = gc.get_outlet(element[-1])
    return msg.PowerState(node=node, state=state)

def retrieve(nodes, element, configmanager, inputdata):
    if 'outlets' in element:
        gp = greenpool.GreenPile(pdupool)
        for node in nodes:
            gp.spawn(get_outlet, node, configmanager)
        for res in gp:
            yield res
           
        return
    elif element[0] == 'sensors':
        gp = greenpool.GreenPile(pdupool)
        for node in nodes:
            gp.spawn(read_sensors, element, node, configmanager)
        for rsp in gp:
            for datum in rsp:
                yield datum
        return
    else:
        for node in nodes:
            yield  msg.ConfluentResourceUnavailable(node, 'Not implemented')
        return
 
def update(nodes, element, configmanager, inputdata):
    if 'outlets' not in element:
        yield msg.ConfluentResourceUnavailable(node, 'Not implemented')
        return
    for node in nodes:
        gc = GeistClient(node, configmanager)
        newstate = inputdata.powerstate(node)
        gc.set_outlet(element[-1], newstate)
    for res in retrieve(nodes, element, configmanager, inputdata):
        yield res
