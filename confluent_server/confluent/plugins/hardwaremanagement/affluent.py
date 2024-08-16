
# Copyright 2019-2020 Lenovo
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
import socket
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

class WebClient(object):
    def __init__(self, node, configmanager, creds):
        self.node = node
        self.wc = webclient.WebConnection(node, port=443, verifycallback=util.TLSCertVerifier(
            configmanager, node, 'pubkeys.tls_hardwaremanager').verify_cert)
        self.wc.set_basic_credentials(creds[node]['secret.hardwaremanagementuser']['value'], creds[node]['secret.hardwaremanagementpassword']['value'])
    
    async def fetch(self, url, results):
        try:
            rsp, status = await self.wc.grab_json_response_with_status(url)
        except exc.PubkeyInvalid:
            results.put_nowait(msg.ConfluentNodeError(self.node,
                'Mismatch detected between '
                'target certificate fingerprint and '
                'pubkeys.tls_hardwaremanager attribute'))
            return {}
        except (socket.gaierror, socket.herror, TimeoutError) as e:
            results.put_nowait(msg.ConfluentTargetTimeout(self.node, str(e)))
            return {}
        except OSError as e:
            if e.errno == 113:
                results.put_nowait(msg.ConfluentTargetTimeout(self.node))
            else:
                results.put_nowait(msg.ConfluentTargetTimeout(self.node), str(e))
            return {}
        except Exception as e:
            results.put_nowait(msg.ConfluentNodeError(self.node,
                repr(e)))
            return {}
        if status == 401:
            results.put_nowait(msg.ConfluentTargetInvalidCredentials(self.node, 'Unable to authenticate'))
            return {}
        elif status != 200:
            #must be str not bytes
            results.put_nowait(msg.ConfluentNodeError(self.node, 'Unknown error: {} while retrieving {}'.format(rsp, url)))
            return {}
        return rsp
    

async def renotify_me(node, configmanager, myname):
    creds = configmanager.get_node_attributes(
        node, ['secret.hardwaremanagementuser', 'secret.hardwaremanagementpassword'], decrypt=True)
    wc = WebClient(node, configmanager, creds)
    res, status = wc.wc.grab_json_response_with_status('/affluent/systems/renotify', {'subscriber': myname})


def subscribe_discovery(node, configmanager, myname):
    creds = configmanager.get_node_attributes(
        node, ['secret.hardwaremanagementuser', 'secret.hardwaremanagementpassword'], decrypt=True)
    tsock = socket.create_connection((node, 443))
    myip = tsock.getsockname()[0]
    tsock.close()
    if ':' in myip:
        myip = '[{0}]'.format(myip)
    myurl = 'https://{0}/confluent-api/self/register_discovered'.format(myip)
    wc = WebClient(node, configmanager, creds)
    with open('/etc/confluent/tls/cacert.pem') as cain:
        cacert = cain.read()
    wc.wc.grab_json_response('/affluent/cert_authorities/{0}'.format(myname), cacert)
    res, status = wc.wc.grab_json_response_with_status('/affluent/discovery_subscribers/{0}'.format(myname), {'url': myurl, 'authname': node})
    if status == 200:
        agentkey = res['cryptkey']
        configmanager.set_node_attributes({node: {'crypted.selfapikey': {'hashvalue': agentkey}}})
    res, status = wc.wc.grab_json_response_with_status('/affluent/systems/renotify', {'subscriber': myname})

def unsubscribe_discovery(node, configmanager, myname):
    creds = configmanager.get_node_attributes(
        node, ['secret.hardwaremanagementuser', 'secret.hardwaremanagementpassword'], decrypt=True)
    wc = WebClient(node, configmanager, creds)
    res, status = wc.wc.grab_json_response_with_status('/affluent/cert_authorities/{0}'.format(myname), method='DELETE')
    res, status = wc.wc.grab_json_response_with_status('/affluent/discovery_subscribers/{0}'.format(myname), method='DELETE')


def update(nodes, element, configmanager, inputdata):
    for node in nodes:
        yield msg.ConfluentNodeError(node, 'Not Implemented')


def delete(nodes, element, configmanager, inputdata):
    for node in nodes:
        yield msg.ConfluentNodeError(node, 'Not Implemented')


def create(nodes, element, configmanager, inputdata):
    for node in nodes:
        yield msg.ConfluentNodeError(node, 'Not Implemented')


def _run_method(method, workers, results, configmanager, nodes, element):
        creds = configmanager.get_node_attributes(
                nodes, ['secret.hardwaremanagementuser', 'secret.hardwaremanagementpassword'], decrypt=True)
        for node in nodes:
            workers.add(util.spawn(method(configmanager, creds,
                                       node, results, element)))

async def retrieve(nodes, element, configmanager, inputdata):
    results = asyncio.Queue()
    workers = set([])
    if element == ['power', 'state']:
        _run_method(retrieve_power, workers, results, configmanager, nodes, element)
    elif element == ['health', 'hardware']:
        _run_method(retrieve_health, workers, results, configmanager, nodes, element)
    elif element[:3] == ['inventory', 'hardware', 'all']:
        _run_method(retrieve_inventory, workers, results, configmanager, nodes, element)
    elif element[:3] == ['inventory', 'firmware', 'all']:
        _run_method(retrieve_firmware, workers, results, configmanager, nodes, element)
    elif element == ['sensors', 'hardware', 'all']:
        _run_method(list_sensors, workers, results, configmanager, nodes, element)
    elif element[:3] == ['sensors', 'hardware', 'all']:
        _run_method(retrieve_sensors, workers, results, configmanager, nodes, element)
    else:
        for node in nodes:
            yield msg.ConfluentNodeError(node, 'Not Implemented')
        return
    while workers:
        try:
            datum = await asyncio.wait_for(results.get(), 10.0)
            while datum:
                if datum:
                    yield datum
                datum = results.get_nowait()
        except asyncio.QueueEmpty:
            pass
        await asyncio.sleep(0)
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


async def retrieve_inventory(configmanager, creds, node, results, element):
    if len(element) == 3:
        results.put_nowait(msg.ChildCollection('all'))
        results.put_nowait(msg.ChildCollection('system'))
        return
    wc = WebClient(node, configmanager, creds)
    invinfo = await wc.fetch('/affluent/inventory/hardware/all', results)
    if invinfo:
        results.put_nowait(msg.KeyValueData(invinfo, node))


async def retrieve_firmware(configmanager, creds, node, results, element):
    if len(element) == 3:
        results.put_nowait(msg.ChildCollection('all'))
        return
    wc = WebClient(node, configmanager, creds)
    fwinfo = await wc.fetch('/affluent/inventory/firmware/all', results)
    if fwinfo:
        results.put_nowait(msg.Firmware(fwinfo, node))

async def list_sensors(configmanager, creds, node, results, element):
    wc = WebClient(node, configmanager, creds)
    sensors = await wc.fetch('/affluent/sensors/hardware/all', results)
    for sensor in sensors['item']:
        results.put_nowait(msg.ChildCollection(sensor))

async def retrieve_sensors(configmanager, creds, node, results, element):
    wc = WebClient(node, configmanager, creds)
    sensors = await wc.fetch('/affluent/sensors/hardware/all/{0}'.format(element[-1]), results)
    if sensors:
        results.put_nowait(msg.SensorReadings(sensors['sensors'], node))



async def retrieve_power(configmanager, creds, node, results, element):
    wc = WebClient(node, configmanager, creds)
    hinfo = await wc.fetch('/affluent/health', results)
    if hinfo:
        results.put_nowait(msg.PowerState(node=node, state='on'))

async def retrieve_health(configmanager, creds, node, results, element):
    wc = WebClient(node, configmanager, creds)
    hinfo = await wc.fetch('/affluent/health', results)
    if hinfo:
        results.put_nowait(msg.HealthSummary(hinfo.get('health', 'unknown'), name=node))
        results.put_nowait(msg.SensorReadings(hinfo.get('sensors', []), name=node))
