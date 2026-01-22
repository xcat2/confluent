
# Copyright 2019 Lenovo
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


#Noncritical:
#  - One or more temperature sensors is in the warning range;
#  - A panic dump exists in flash.
#Critical:
#  - One or more temperature sensors is in the failure range;
#  - One or more fans are running < 100 RPM;
#  - One power supply is off.


import asyncio
from confluent import tasks
import confluent.exceptions as exc
import aiohmi.util.webclient as webclient
import confluent.messages as msg
import confluent.util as util

class SwitchSensor(object):
    def __init__(self, name, states, value=None, health=None):
        self.name = name
        self.value = value
        self.states = states
        self.health = health


async def cnos_login(node, configmanager, creds):
    wc = webclient.WebConnection(node, port=443, verifycallback=util.TLSCertVerifier(
        configmanager, node, 'pubkeys.tls_hardwaremanager').verify_cert)
    wc.set_basic_credentials(creds[node]['secret.hardwaremanagementuser']['value'], creds[node]['secret.hardwaremanagementpassword']['value'])
    body, status, headers = await wc.grab_response_with_status('/nos/api/login/')
    if status == 401:  # CNOS gives 401 on first attempt...
        body, status, headers = await wc.grab_response_with_status('/nos/api/login/')
    if status >= 200 and status < 300:
        return wc
    raise exc.TargetEndpointBadCredentials('Unable to authenticate')

async def update(nodes, element, configmanager, inputdata):
    for node in nodes:
        yield msg.ConfluentNodeError(node, 'Not Implemented')

async def delete(nodes, element, configmanager, inputdata):
    for node in nodes:
        yield msg.ConfluentNodeError(node, 'Not Implemented')

async def create(nodes, element, configmanager, inputdata):
    for node in nodes:
        yield msg.ConfluentNodeError(node, 'Not Implemented')




async def retrieve_inventory(configmanager, creds, node, results, element):
    if len(element) == 3:
        await results.put(msg.ChildCollection('all'))
        await results.put(msg.ChildCollection('system'))
        return
    wc = await cnos_login(node, configmanager, creds)
    sysinfo = await wc.grab_json_response('/nos/api/sysinfo/inventory')
    invinfo = {
        'inventory': [{
            'name': 'System',
            'present': True,
            'information': {
                'Product name': sysinfo['Model'],
                'Serial Number': sysinfo['Electronic Serial Number'],
                'Board Serial Number': sysinfo['Serial Number'],
                'Manufacturer': 'Lenovo',
                'Model': sysinfo['Machine Type Model'],
                'FRU Number': sysinfo['FRU'].strip(),
            }
        }]
    }
    await results.put(msg.KeyValueData(invinfo, node))


async def retrieve_firmware(configmanager, creds, node, results, element):
    if len(element) == 3:
        await results.put(msg.ChildCollection('all'))
        return
    wc = await cnos_login(node, configmanager, creds)
    sysinfo = await wc.grab_json_response('/nos/api/sysinfo/inventory')
    items = [{
        'Software': {'version': sysinfo['Software Revision']},
        },
        {
        'BIOS': {'version': sysinfo['BIOS Revision']},
        }]
    await results.put(msg.Firmware(items, node))

async def retrieve_health(configmanager, creds, node, results):
    wc = await cnos_login(node, configmanager, creds)
    hinfo = await wc.grab_json_response('/nos/api/sysinfo/globalhealthstatus')
    summary = hinfo['status'].lower()
    if summary == 'noncritical':
        summary = 'warning'
    await results.put(msg.HealthSummary(summary, name=node))
    state = None
    badreadings = []
    if summary != 'ok':  # temperature or dump or fans or psu
        await wc.grab_json_response('/nos/api/sysinfo/panic_dump')
        switchinfo = await wc.grab_json_response('/nos/api/sysinfo/panic_dump')
        if switchinfo:
            badreadings.append(
                SwitchSensor('Panicdump', ['Present'], health='warning'))
        switchinfo = await wc.grab_json_response('/nos/api/sysinfo/temperatures')
        for temp in switchinfo:
            if temp == 'Temperature threshold':
                continue
            if switchinfo[temp]['State'] != 'OK':
                temphealth = switchinfo[temp]['State'].lower()
                if temphealth == 'noncritical':
                    temphealth = 'warning'
                tempval = switchinfo[temp]['Temp']
                badreadings.append(
                    SwitchSensor(temp, [], value=tempval, health=temphealth))
        switchinfo = await wc.grab_json_response('/nos/api/sysinfo/fans')
        for fan in switchinfo:
            if switchinfo[fan]['speed-rpm'] < 100:
                badreadings.append(
                    SwitchSensor(fan, [], value=switchinfo[fan]['speed-rpm'],
                                 health='critical'))
        switchinfo = await wc.grab_json_response('/nos/api/sysinfo/power')
        for psu in switchinfo:
            if switchinfo[psu]['State'] != 'Normal ON':
                psuname = switchinfo[psu]['Name']
                badreadings.append(
                    SwitchSensor(psuname, states=[switchinfo[psu]['State']],
                                 health='critical'))
    await results.put(msg.SensorReadings(badreadings, name=node))

async def retrieve(nodes, element, configmanager, inputdata):
    results = asyncio.Queue()
    workers = set([])
    if element == ['power', 'state']:
        for node in nodes:
            yield msg.PowerState(node=node, state='on')
        return
    elif element == ['health', 'hardware']:
        creds = configmanager.get_node_attributes(
                nodes, ['secret.hardwaremanagementuser', 'secret.hardwaremanagementpassword'], decrypt=True)
        for node in nodes:
            workers.add(tasks.spawn(retrieve_health(configmanager, creds,
                                       node, results)))
    elif element[:3] == ['inventory', 'hardware', 'all']:
        creds = configmanager.get_node_attributes(
                nodes, ['secret.hardwaremanagementuser', 'secret.hardwaremanagementpassword'], decrypt=True)
        for node in nodes:
            workers.add(tasks.spawn(retrieve_inventory(configmanager,
                                       creds, node, results, element)))
    elif element[:3] == ['inventory', 'firmware', 'all']:
        creds = configmanager.get_node_attributes(
                nodes, ['secret.hardwaremanagementuser', 'secret.hardwaremanagementpassword'], decrypt=True)
        for node in nodes:
            workers.add(tasks.spawn(retrieve_firmware(configmanager,
                                       creds, node, results, element)))
    else:
        for node in nodes:
            yield msg.ConfluentNodeError(node, 'Not Implemented')
        return
    currtimeout = 10
    while workers:
        try:
            datum = await asyncio.wait_for(results.get(), timeout=10)
            while datum:
                if datum:
                    yield datum
                datum = results.get_nowait()
        except asyncio.QueueEmpty:
            pass
        await asyncio.sleep(0.001)
        for t in list(workers):
            if t.done():
                workers.discard(t)
    try:
        while True:
            datum = results.get_nowait()
            if datum:
                yield datum
    except asyncio.QueueEmpty:
        pass
