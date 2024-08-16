
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


import eventlet
import eventlet.queue as queue
import eventlet.green.socket as socket
import confluent.exceptions as exc
webclient = eventlet.import_patched('pyghmi.util.webclient')
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
        self.wc = webclient.SecureHTTPConnection(node, port=443, verifycallback=util.TLSCertVerifier(
            configmanager, node, 'pubkeys.tls_hardwaremanager').verify_cert)
        self.wc.set_basic_credentials(creds[node]['secret.hardwaremanagementuser']['value'], creds[node]['secret.hardwaremanagementpassword']['value'])
    
    def fetch(self, url, results):
        try:
            rsp, status = self.wc.grab_json_response_with_status(url)
        except exc.PubkeyInvalid:
            results.put(msg.ConfluentNodeError(self.node,
                'Mismatch detected between '
                'target certificate fingerprint and '
                'pubkeys.tls_hardwaremanager attribute'))
            return {}
        except (socket.gaierror, socket.herror, TimeoutError) as e:
            results.put(msg.ConfluentTargetTimeout(e.strerror))
            return {}
        except Exception as e:
            results.put(msg.ConfluentNodeError(self.node,
                repr(e)))
            return {}
        if status == 401:
            results.put(msg.ConfluentTargetInvalidCredentials(self.node, 'Unable to authenticate'))
            return {}
        elif status != 200:
            #must be str not bytes
            results.put(msg.ConfluentNodeError(self.node, 'Unknown error: {} while retrieving {}'.format(rsp, url)))
            return {}
        return rsp
    

def renotify_me(node, configmanager, myname):
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
            workers.add(eventlet.spawn(method, configmanager, creds,
                                       node, results, element))

def retrieve(nodes, element, configmanager, inputdata):
    results = queue.LightQueue()
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
            datum = results.get(block=True, timeout=10)
            while datum:
                if datum:
                    yield datum
                datum = results.get_nowait()
        except queue.Empty:
            pass
        eventlet.sleep(0.001)
        for t in list(workers):
            if t.dead:
                workers.discard(t)
    try:
        while True:
            datum = results.get_nowait()
            if datum:
                yield datum
    except queue.Empty:
        pass


def retrieve_inventory(configmanager, creds, node, results, element):
    if len(element) == 3:
        results.put(msg.ChildCollection('all'))
        results.put(msg.ChildCollection('system'))
        return
    wc = WebClient(node, configmanager, creds)
    invinfo = wc.fetch('/affluent/inventory/hardware/all', results)
    if invinfo:
        results.put(msg.KeyValueData(invinfo, node))


def retrieve_firmware(configmanager, creds, node, results, element):
    if len(element) == 3:
        results.put(msg.ChildCollection('all'))
        return
    wc = WebClient(node, configmanager, creds)
    fwinfo = wc.fetch('/affluent/inventory/firmware/all', results)
    if fwinfo:
        results.put(msg.Firmware(fwinfo, node))

def list_sensors(configmanager, creds, node, results, element):
    wc = WebClient(node, configmanager, creds)
    sensors = wc.fetch('/affluent/sensors/hardware/all', results)
    for sensor in sensors['item']:
        results.put(msg.ChildCollection(sensor))

def retrieve_sensors(configmanager, creds, node, results, element):
    wc = WebClient(node, configmanager, creds)
    sensors = wc.fetch('/affluent/sensors/hardware/all/{0}'.format(element[-1]), results)
    if sensors:
        results.put(msg.SensorReadings(sensors['sensors'], node))



def retrieve_power(configmanager, creds, node, results, element):
    wc = WebClient(node, configmanager, creds)
    hinfo = wc.fetch('/affluent/health', results)
    if hinfo:
        results.put(msg.PowerState(node=node, state='on'))

def retrieve_health(configmanager, creds, node, results, element):
    wc = WebClient(node, configmanager, creds)
    hinfo = wc.fetch('/affluent/health', results)
    if hinfo:
        results.put(msg.HealthSummary(hinfo.get('health', 'unknown'), name=node))
        results.put(msg.SensorReadings(hinfo.get('sensors', []), name=node))
