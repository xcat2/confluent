
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


import eventlet
import confluent.exceptions as exc
webclient = eventlet.import_patched('pyghmi.util.webclient')
import confluent.messages as msg
import confluent.util as util

class SwitchSensor(object):
    def __init__(self, name, states, value=None, health=None):
        self.name = name
        self.value = value
        self.states = states


def cnos_login(node, configmanager, creds):
    wc = webclient.SecureHTTPConnection(node, port=443, verifycallback=util.TLSCertVerifier(
        configmanager, node, 'pubkeys.tls_hardwaremanager').verify_cert)
    wc.set_basic_credentials(creds[node]['secret.hardwaremanagementuser']['value'], creds[node]['secret.hardwaremanagementpassword']['value'])
    wc.request('GET', '/nos/api/login/')
    rsp = wc.getresponse()
    body = rsp.read()
    if rsp.status == 401:  # CNOS gives 401 on first attempt...
        wc.request('GET', '/nos/api/login/')
        rsp = wc.getresponse()
        body = rsp.read()
    if rsp.status >= 200 and rsp.status < 300:
        return wc
    raise exc.TargetEndpointBadCredentials('Unable to authenticate')

def retrieve(nodes, element, configmanager, inputdata):
    if element == ['power', 'state']:
        for node in nodes:
            yield msg.PowerState(node=node, state='on')
    if element == ['health', 'hardware']:
        creds = configmanager.get_node_attributes(
                nodes, ['secret.hardwaremanagementuser', 'secret.hardwaremanagementpassword'], decrypt=True)
        for node in nodes:
            wc = cnos_login(node, configmanager, creds)
            hinfo = wc.grab_json_response('/nos/api/sysinfo/globalhealthstatus')
            summary = hinfo['status'].lower()
            if summary == 'noncritical':
                summary = 'warning'
            yield msg.HealthSummary(summary, name=node)
            state = None
            badreadings = []
            if summary != 'ok':  # temperature or dump or fans or psu
                wc.grab_json_response('/nos/api/sysinfo/panic_dump')
                switchinfo = wc.grab_json_response('/nos/api/sysinfo/panic_dump')
                if switchinfo:
                    badreadings.append(SwitchSensor('Panicdump', ['Present'], health='warning'))
                switchinfo = wc.grab_json_response('/nos/api/sysinfo/temperatures')
                for temp in switchinfo:
                    if temp == 'Temperature threshold':
                        continue
                    if switchinfo[temp]['State'] != 'OK':
                        temphealth = switchinfo[temp]['State'].lower()
                        if temphealth == 'noncritical':
                            temphealth = 'warning'
                        tempval = switchinfo[temp]['Temp']
                        badreadings.append(SwitchSensor(temp, [], value=tempval, health=temphealth))
                switchinfo = wc.grab_json_response('/nos/api/sysinfo/fans')
                for fan in switchinfo:
                    if switchinfo[fan]['speed-rpm'] < 100:
                        badreadings.append(SwitchSensor(fan, [], value=switchinfo[fan]['speed-rpm'], health='critical'))
                switchinfo = wc.grab_json_response('/nos/api/sysinfo/power')
                for psu in switchinfo:
                    if switchinfo[psu]['State'] != 'Normal ON':
                        psuname = switchinfo[psu]['Name']
                        badreadings.append(SwitchSensor(psuname, states=[switchinfo[psu]['State']], health='critical'))
            yield msg.SensorReadings(badreadings, name=node)

