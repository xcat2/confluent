# Copyright 2022 Lenovo
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import pyghmi.util.webclient as wc
import confluent.util as util
import confluent.messages as msg
import confluent.exceptions as exc
import eventlet.green.time as time
import eventlet
import eventlet.greenpool as greenpool



def simplify_name(name):
    return name.lower().replace(' ', '_').replace('/', '-').replace('_-_', '-')


pdupool = greenpool.GreenPool(128)

_pduclients = {}


class EnlogicClient(object):
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
            print("done cache")
            return self._wc
        print("loggin")
        targcfg = self.configmanager.get_node_attributes(
            self.node, ['hardwaremanagement.manager'], decrypt=True
        )
        targcfg = targcfg.get(self.node, {})
        target = targcfg.get('hardwaremanagement.manager', {}).get('value', None)
        if not target:
            target = self.node
        target = target.split('/', 1)[0]
        cv = util.TLSCertVerifier(
            self.configmanager, self.node, 'pubkeys.tls_hardwaremanager'
        ).verify_cert
        self._wc = wc.SecureHTTPConnection(target, port=443, verifycallback=cv)
        return self._wc

    def grab_json_response(self, url, body=None):
        rsp, status = self.wc.grab_json_response_with_status(url, body)
        if status == 401:
            self._token = None
        if body and 'cookie' in body:
            body['cookie'] = self.token
        rsp, status = self.wc.grab_json_response_with_status(url, body)
        if status < 300:
            return rsp
        return {}

    def login(self, configmanager):
        credcfg = configmanager.get_node_attributes(
            self.node,
            ['secret.hardwaremanagementuser', 'secret.hardwaremanagementpassword'],
            decrypt=True,
        )
        credcfg = credcfg.get(self.node, {})
        username = credcfg.get('secret.hardwaremanagementuser', {}).get('value', None)
        passwd = credcfg.get('secret.hardwaremanagementpassword', {}).get('value', None)

        if not isinstance(username, str):
            username = username.decode('utf8')
        if not isinstance(passwd, str):
            passwd = passwd.decode('utf8')
        if not username or not passwd:
            raise Exception('Missing username or password')
        self.username = username
        rsp = self.wc.grab_json_response(
            '/xhrlogin.jsp',
            {'username':  username, 'password': passwd, 'cookie': 0}
        )
        print(repr(rsp))
        self.authtoken = rsp['cookie']
        self.wc.set_header('Authorization', self.authtoken)
        return self.authtoken

    def logout(self):
        if self._token:
            self.wc.grab_json_response(
                '/xhrlogout.jsp',
                {'timeout': 0, 'cookie': self._token},
            )
            self._token = None

    def get_outlet(self, outlet):
        rsp = self.grab_json_response(
            '/xhroutgetgrid.jsp', {
                'cookie': self.token,
                'pduid': 1
                })
        outlets = rsp['outlet']
        for olet in outlets:
            if olet['id'] == int(outlet):
                state = "on" if olet['powstat'] == 1 else "off"
                return state

    def set_outlet(self, outlet, state):
        bitflags = 2**(int(outlet) - 1)
        outlet1 = bitflags & (2**24-1)
        outlet2 = bitflags >> 24
        if state == 'off':
            state = 0
        elif state == 'on':
            state = 1
        else:
            raise Exception("Unrecognized state " + repr(state))
        request = {
            'cookie': self.token,
            'outlet1': outlet1,
            'outlet2': outlet2,
            'pduid': 1,
            'powstat': state
            }
        rsp = self.grab_json_response('/xhroutpowstatset.jsp', request)


_sensors_by_node = {}


def read_sensors(element, node, configmanager):
    category, name = element[-2:]
    justnames = False
    if len(element) == 3:
        # just get names
        category = name
        name = 'all'
        justnames = True
    if category in ('leds, fans', 'temperature'):
        return
    if justnames:
        yield msg.ChildCollection('total_energy')
        yield msg.ChildCollection('total_apparent_power')
        yield msg.ChildCollection('total_real_power')
        return
    sn = _sensors_by_node.get(node, None)
    if not sn or sn[1] < time.time():
        gc = get_client(node, configmanager)
        adev = gc.grab_json_response('/energy_get', {'cookie': gc.token, 'end': 1, 'start': 1})
        _sensors_by_node[node] = (adev, time.time() + 1)
        sn = _sensors_by_node.get(node, None)
    if sn:
        sn = sn[0]
    readings = [
        {
            'name': 'Total Energy',
            'value': float(sn[0]['total_energy']) * 0.001,
            'units': 'kWh',
            'type': 'Energy',
        },
        {
            'name': 'Total Real Power',
            'value': float(sn[0]['active_power']),
            'units': 'W',
            'type': 'Power',
        },
        {
            'name': 'Total Apparent Power',
            'value': float(sn[0]['apparent_power']),
            'units': 'W',
            'type': 'Power',
        },
    ]
    yield msg.SensorReadings(readings, name=node)
    return

def get_client(node, configmanager):
    if node not in _pduclients:
        _pduclients[node] = EnlogicClient(node, configmanager)
    return _pduclients[node]

def get_outlet(element, node, configmanager):
    gc = get_client(node, configmanager)
    state = gc.get_outlet(element[-1])
    return msg.PowerState(node=node, state=state)


def read_firmware(node, configmanager):
    gc = get_client(node, configmanager)
    adev = gc.grab_json_response('/xhrgetuserlist.jsp')
    myversion = adev[0]['fwver']
    yield msg.Firmware([{'PDU Firmware': {'version': myversion}}], node)


def read_inventory(element, node, configmanager):
    _inventory = {}
    inventory = {}
    gc = get_client(node, configmanager)
    adev = gc.grab_json_response('/sys_info_get', {
        'cookie': gc.token, 'pduid': 1
        })
    inventory['present'] = True
    inventory['name'] = 'PDU'
    info = {}
    info['Serial Number'] = adev['pdu'][0]['serial_number']
    info['Product Name'] = adev['pdu'][0]['model']
    info['Model'] = adev['pdu'][0]['part_number']
    inventory['information'] = info
    yield msg.KeyValueData({'inventory': [inventory]}, node)

def retrieve(nodes, element, configmanager, inputdata):

    if 'outlets' in element:
        gp = greenpool.GreenPile(pdupool)
        for node in nodes:

            gp.spawn(get_outlet, element, node, configmanager)
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
    elif '/'.join(element).startswith('inventory/firmware/all'):
        gp = greenpool.GreenPile(pdupool)
        for node in nodes:
            gp.spawn(read_firmware, node, configmanager)
        for rsp in gp:
            for datum in rsp:
                yield datum

    elif '/'.join(element).startswith('inventory/hardware/all'):
        gp = greenpool.GreenPile(pdupool)
        for node in nodes:
            gp.spawn(read_inventory, element, node, configmanager)
        for rsp in gp:
            for datum in rsp:
                yield datum
    else:
        for node in nodes:
            yield msg.ConfluentResourceUnavailable(node, 'Not implemented')
        return


def update(nodes, element, configmanager, inputdata):
    if 'outlets' not in element:
        for node in nodes:
            yield msg.ConfluentResourceUnavailable(node, 'Not implemented')
        return
    for node in nodes:
        gc = get_client(node, configmanager)
        newstate = inputdata.powerstate(node)
        gc.set_outlet(element[-1], newstate)
    eventlet.sleep(1)
    for res in retrieve(nodes, element, configmanager, inputdata):
        yield res
