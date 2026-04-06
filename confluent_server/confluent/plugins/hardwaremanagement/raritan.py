# Copyright 2022-2026 Lenovo
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

# Plugin for Raritan PDUs using JSON-RPC over HTTPS

import asyncio
import base64
import confluent.util as util
import confluent.messages as msg
import confluent.exceptions as exc
import aiohmi.util.webclient as wc
import confluent.tasks as tasks
import json
import time


def simplify_name(name):
    return name.lower().replace(' ', '_').replace('/', '-').replace('_-_', '-')


pdupool = tasks.TaskPool(128)

_state_to_str = {
    0: 'off',
    1: 'on',
}

_str_to_state = {
    'off': 0,
    'on': 1,
}

# Raritan sensor type IDs to human-readable names and categories
_sensor_type_map = {
    'rmsCurrent': ('Current', 'A', 'all'),
    'rmsVoltage': ('Voltage', 'V', 'all'),
    'activePower': ('Active Power', 'W', 'power'),
    'apparentPower': ('Apparent Power', 'VA', 'power'),
    'reactivePower': ('Reactive Power', 'var', 'power'),
    'powerFactor': ('Power Factor', '', 'all'),
    'activeEnergy': ('Energy', 'Wh', 'energy'),
    'lineFrequency': ('Line Frequency', 'Hz', 'all'),
    'temperature': ('Temperature', 'deg C', 'all'),
    'humidity': ('Humidity', '%', 'all'),
    'airPressure': ('Air Pressure', 'Pa', 'all'),
}


class RaritanClient(object):
    def __init__(self, pdu, configmanager):
        self.node = pdu
        self.configmanager = configmanager
        self._wc = None
        self._authheader = None
        self._jsonrpc_id = 0
        self._pdu_metadata = None
        self._num_outlets = None

    def _next_id(self):
        self._jsonrpc_id += 1
        return self._jsonrpc_id

    @property
    def wc(self):
        if self._wc:
            return self._wc
        targcfg = self.configmanager.get_node_attributes(
            self.node, ['hardwaremanagement.manager'], decrypt=True
        )
        targcfg = targcfg.get(self.node, {})
        target = targcfg.get('hardwaremanagement.manager', {}).get(
            'value', None
        )
        if not target:
            target = self.node
        target = target.split('/', 1)[0]
        cv = util.TLSCertVerifier(
            self.configmanager, self.node, 'pubkeys.tls_hardwaremanager'
        ).verify_cert
        self._wc = wc.WebConnection(target, port=443, verifycallback=cv)
        return self._wc

    @property
    def authheader(self):
        if self._authheader:
            return self._authheader
        credcfg = self.configmanager.get_node_attributes(
            self.node,
            [
                'secret.hardwaremanagementuser',
                'secret.hardwaremanagementpassword',
            ],
            decrypt=True,
        )
        credcfg = credcfg.get(self.node, {})
        username = credcfg.get('secret.hardwaremanagementuser', {}).get(
            'value', None
        )
        passwd = credcfg.get('secret.hardwaremanagementpassword', {}).get(
            'value', None
        )
        if not username or not passwd:
            raise Exception('Missing username or password')
        if not isinstance(username, str):
            username = username.decode('utf8')
        if not isinstance(passwd, str):
            passwd = passwd.decode('utf8')
        cred = base64.b64encode(
            '{0}:{1}'.format(username, passwd).encode('utf8')
        ).decode('utf8')
        self._authheader = {'Authorization': 'Basic ' + cred}
        return self._authheader

    async def bulk_jsonrpc(self, ump):
        requests = []
        reqmeth = 'performBulk'
        reqpath = '/bulk'
        reqparms = {'requests': requests}
        uribyid = {}
        for req in ump:
            reqid = self._next_id()
            uri, method, params = req
            uribyid[reqid] = uri
            currreq = {
                'rid': uri,
                'json': {
                    'jsonrpc': '2.0',
                    'method': method,
                    'id': reqid,
                },
            }
            if params is not None:
                currreq['json']['params'] = params
            requests.append(currreq)
        rsps = await self.jsonrpc(reqpath, reqmeth, reqparms)
        rsps = rsps.get('responses', [])
        result_by_uri = {}
        for rsp in rsps:
            uri = uribyid.get(rsp['json']['id'], None)
            if uri:
                result_by_uri[uri] = rsp['json']['result']
        return result_by_uri


    async def jsonrpc(self, uri, method, params=None):
        reqdata = {
            'jsonrpc': '2.0',
            'method': method,
            'id': self._next_id(),
        }
        if params is not None:
            reqdata['params'] = params
        rsp = await self.wc.grab_json_response(
            uri, reqdata, headers=self.authheader
        )
        if 'error' in rsp and rsp['error']:
            raise Exception(
                'Raritan JSON-RPC error: {}'.format(rsp['error'])
            )
        return rsp.get('result', {})

    async def get_pdu_metadata(self):
        if self._pdu_metadata is None:
            result = await self.jsonrpc('/model/pdu/0', 'getMetaData')
            self._pdu_metadata = result.get('_ret_', {})
        return self._pdu_metadata

    async def get_num_outlets(self):
        if self._num_outlets is None:
            result = await self.jsonrpc('/model/pdu/0', 'getOutlets')
            self._num_outlets = len(result.get('_ret_', []))
        return self._num_outlets

    async def get_outlet_state(self, outlet):
        # outlet is 1-based from confluent, Raritan is 0-based
        idx = int(outlet) - 1
        result = await self.jsonrpc(
            '/model/pdu/0/outlet/{0}'.format(idx), 'getState'
        )
        ret = result.get('_ret_', {})
        pstate = ret.get('powerState', 0)
        return _state_to_str.get(pstate, 'off')

    async def set_outlet_state(self, outlet, state):
        idx = int(outlet) - 1
        pstate = _str_to_state.get(state, None)
        if pstate is None:
            if state == 'boot':
                # power cycle
                await self.jsonrpc(
                    '/model/pdu/0/outlet/{0}'.format(idx),
                    'cyclePowerState',
                )
                return
            raise Exception('Unsupported power state: {}'.format(state))
        await self.jsonrpc(
            '/model/pdu/0/outlet/{0}'.format(idx),
            'setPowerState',
            {'pstate': pstate},
        )

    async def get_inlet_sensors(self):
        result = await self.jsonrpc('/model/inlet/0', 'getSensors')
        return result.get('_ret_', {})

    async def get_outlet_sensors(self, outlet_idx):
        result = await self.jsonrpc(
            '/model/pdu/0/outlet/{0}'.format(outlet_idx), 'getSensors'
        )
        return result.get('_ret_', {})

    async def get_outlet_metadata(self, outlet_idx):
        result = await self.jsonrpc(
            '/model/pdu/0/outlet/{0}'.format(outlet_idx), 'getMetaData'
        )
        return result.get('_ret_', {})

    async def get_peripheral_slots(self):
        result = await self.jsonrpc(
            '/model/peripheraldevicemanager', 'getDeviceSlots'
        )
        return result.get('_ret_', [])


_sensors_by_node = {}


async def _collect_sensor_readings(rc, name, category):
    readings = []
    # Inlet sensors
    inlet_sensors = await rc.get_inlet_sensors()
    read_requests = []
    infobyrid = {}
    for stype, sref in inlet_sensors.items():
        if sref is None:
            continue
        info = _sensor_type_map.get(stype, None)
        if not info:
            continue
        readtype, units, cat = info
        if category not in ('all', cat):
            continue
        myname = 'Inlet ' + readtype
        if name != 'all' and simplify_name(myname) != name:
            continue
        sensor_rid = sref.get('rid', None) if isinstance(sref, dict) else None
        if not sensor_rid:
            continue
        infobyrid[sensor_rid] = (myname, units, readtype)
        read_requests.append((sensor_rid, 'getReading', None))
    # Outlet sensors
    num_outlets = await rc.get_num_outlets()
    outlet_by_url = {}
    bulkreqs = []
    for idx in range(num_outlets):
        outlet_by_url['/model/pdu/0/outlet/{0}'.format(idx)] = idx
        bulkreqs.append(('/model/pdu/0/outlet/{0}'.format(idx), 'getSensors', None))
    rsps = await rc.bulk_jsonrpc(bulkreqs)
    bulkreqs = []
    for url in rsps:
        idx = outlet_by_url.get(url, None)
        if idx is not None:
            outlet_label = 'Outlet {}'.format(idx + 1)
            outlet_sensors = rsps[url].get('_ret_', {})
            for stype, sref in outlet_sensors.items():
                if sref is None:
                    continue
                info = _sensor_type_map.get(stype, None)
                if not info:
                    continue
                readtype, units, cat = info
                if category not in ('all', cat):
                    continue
                myname = outlet_label + ' ' + readtype
                if name != 'all' and simplify_name(myname) != name:
                    continue
                sensor_rid = (
                    sref.get('rid', None) if isinstance(sref, dict) else None
                )
                if not sensor_rid:
                    continue
                infobyrid[sensor_rid] = (myname, units, readtype)
                read_requests.append((sensor_rid, 'getReading', None))
    # Peripheral device sensors (temperature, humidity, etc.)
    try:
        slots = await rc.get_peripheral_slots()
        bulksettingsrequests = []
        bulkdevicerequests = []
        for slotref in slots:
            slot_rid = (
                slotref.get('rid', None)
                if isinstance(slotref, dict) else None
            )
            if not slot_rid:
                continue
            bulksettingsrequests.append((slot_rid, 'getSettings', None))
            bulkdevicerequests.append((slot_rid, 'getDevice', None))
        bulksettings = await rc.bulk_jsonrpc(bulksettingsrequests)
        bulkdevices = {}
        for setting in bulksettings.values():
            setting = setting.get('_ret_', {})
            if setting.get('name', '') != '':
                break
        else:
            bulkdevicerequests = []
        if bulkdevicerequests:
            bulkdevices = await rc.bulk_jsonrpc(bulkdevicerequests)
        for slotref in slots:
            slot_rid = (
                slotref.get('rid', None)
                if isinstance(slotref, dict) else None
            )
            if not slot_rid:
                continue
            settings = bulksettings.get(slot_rid, {}).get('_ret_', {})
            devinfo = bulkdevices.get(slot_rid, {}).get('_ret_', {})
            if not devinfo or devinfo.get('device', None) is None:
                continue
            sensor_name = settings.get('name', 'Peripheral Sensor')
            dev_rid = devinfo['device'].get('rid', None)
            if not dev_rid:
                continue
            dev_type = devinfo.get('deviceID', {}).get('type', {})
            reading_type = dev_type.get('readingtype', 0)
            # readingtype 0 = numeric, 1 = state
            if reading_type == 0:
                readtype = dev_type.get('type', 'numeric')
                info = _sensor_type_map.get(readtype, None)
                if info:
                    rname, units, cat = info
                else:
                    rname = readtype.replace('_', ' ').title()
                    units = ''
                    cat = 'all'
                if category not in ('all', cat):
                    continue
                myname = sensor_name + ' ' + rname
                if name != 'all' and simplify_name(myname) != name:
                    continue
                infobyrid[dev_rid] = (myname, units, rname)
                read_requests.append((dev_rid, 'getReading', None))
    except Exception:
        pass
    rsps = await rc.bulk_jsonrpc(read_requests)
    for sensor_rid, result in rsps.items():
        reading = result.get('_ret_', {})
        myname, units, readtype = infobyrid.get(sensor_rid, ('Unknown', '', ''))
        readings.append({
            'name': myname,
            'value': float(reading.get('value', 0)),
            'units': units,
            'type': readtype.split()[-1],
        })
    return readings


async def read_sensors(element, node, configmanager):
    category, name = element[-2:]
    justnames = False
    if len(element) == 3:
        category = name
        name = 'all'
        justnames = True
    if category in ('leds', 'fans'):
        return
    sn = _sensors_by_node.get(node, None)
    if sn and sn[1] >= time.time():
        readings = sn[0]
    else:
        rc = RaritanClient(node, configmanager)
        readings = await _collect_sensor_readings(rc, 'all', 'all')
        _sensors_by_node[node] = (readings, time.time() + 1)
    # filter readings by requested name/category
    filtered = []
    for r in readings:
        rtype = r['type'].lower().replace(' ', '')
        matching_cat = 'all'
        for key, info in _sensor_type_map.items():
            if info[0].split()[-1].lower() == rtype:
                matching_cat = info[2]
                break
        if category not in ('all', matching_cat):
            continue
        if name != 'all' and simplify_name(r['name']) != name:
            continue
        filtered.append(r)
    if justnames:
        for reading in filtered:
            return msg.ChildCollection(simplify_name(reading['name']))
    else:
        return msg.SensorReadings(filtered, name=node)


async def get_outlet(element, node, configmanager):
    rc = RaritanClient(node, configmanager)
    state = await rc.get_outlet_state(element[-1])
    return msg.PowerState(node=node, state=state)


async def read_firmware(node, configmanager):
    rc = RaritanClient(node, configmanager)
    metadata = await rc.get_pdu_metadata()
    version = metadata.get('fwRevision', 'Unknown')
    return msg.Firmware([{'PDU Firmware': {'version': version}}], node)


async def read_inventory(element, node, configmanager):
    rc = RaritanClient(node, configmanager)
    metadata = await rc.get_pdu_metadata()
    nameplate = metadata.get('nameplate', {})
    rating = nameplate.get('rating', {})
    _inventory = {}
    inventory = {}
    inventory['present'] = True
    inventory['name'] = 'PDU'
    if nameplate.get('manufacturer'):
        _inventory['Manufacturer'] = nameplate['manufacturer']
    if nameplate.get('model'):
        _inventory['Model'] = nameplate['model']
    if nameplate.get('partNumber'):
        _inventory['P/N'] = nameplate['partNumber']
    if nameplate.get('serialNumber'):
        _inventory['Serial'] = nameplate['serialNumber']
    if metadata.get('hwRevision'):
        _inventory['Hardware Revision'] = metadata['hwRevision']
    if metadata.get('macAddress'):
        _inventory['MAC Address'] = metadata['macAddress']
    if rating.get('voltage'):
        _inventory['Voltage Rating'] = rating['voltage']
    if rating.get('current'):
        _inventory['Current Rating'] = rating['current']
    if rating.get('frequency'):
        _inventory['Frequency Rating'] = rating['frequency']
    if rating.get('power'):
        _inventory['Power Rating'] = rating['power']
    inventory['information'] = _inventory
    return msg.KeyValueData({'inventory': [inventory]}, node)


async def list_outlets(node, configmanager):
    rc = RaritanClient(node, configmanager)
    num_outlets = await rc.get_num_outlets()
    for idx in range(num_outlets):
        yield msg.ChildCollection(str(idx + 1))


async def retrieve(nodes, element, configmanager, inputdata):
    if 'outlets' in element:
        if element[-1] == 'outlets':
            for node in nodes:
                async for res in list_outlets(node, configmanager):
                    yield res
            return
        gp = tasks.TaskPile(pdupool)
        for node in nodes:
            gp.spawn(get_outlet, element, node, configmanager)
        async for res in gp:
            yield res
        return
    elif element[0] == 'sensors':
        gp = tasks.TaskPile(pdupool)
        for node in nodes:
            gp.spawn(read_sensors, element, node, configmanager)
        async for rsp in gp:
            yield rsp
        return
    elif '/'.join(element).startswith('inventory/firmware/all'):
        gp = tasks.TaskPile(pdupool)
        for node in nodes:
            gp.spawn(read_firmware, node, configmanager)
        async for rsp in gp:
            yield rsp
    elif '/'.join(element).startswith('inventory/hardware/all'):
        gp = tasks.TaskPile(pdupool)
        for node in nodes:
            gp.spawn(read_inventory, element, node, configmanager)
        async for rsp in gp:
            yield rsp
    else:
        for node in nodes:
            yield msg.ConfluentResourceUnavailable(node, 'Not implemented')
        return


async def update(nodes, element, configmanager, inputdata):
    if 'outlets' not in element:
        for node in nodes:
            yield msg.ConfluentResourceUnavailable(node, 'Not implemented')
        return
    for node in nodes:
        rc = RaritanClient(node, configmanager)
        newstate = inputdata.powerstate(node)
        await rc.set_outlet_state(element[-1], newstate)
    await asyncio.sleep(1)
    async for res in retrieve(nodes, element, configmanager, inputdata):
        yield res
