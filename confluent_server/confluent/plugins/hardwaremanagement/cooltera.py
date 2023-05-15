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
import pyghmi.util.webclient as wc
import confluent.util as util
import confluent.messages as msg
import confluent.exceptions as exc
import eventlet.green.time as time
import eventlet.green.socket as socket
import eventlet.greenpool as greenpool
import eventlet
try:
    import Cookie
    httplib = eventlet.import_patched('httplib')
except ImportError:
    httplib = eventlet.import_patched('http.client')
    import http.cookies as Cookie

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

pdupool = greenpool.GreenPool(128)

class WebResponse(httplib.HTTPResponse):
    def _check_close(self):
        return True

class WebConnection(wc.SecureHTTPConnection):
    response_class = WebResponse
    def __init__(self, host, secure, verifycallback):
        if secure:
            port = 443
        else:
            port = 80
        wc.SecureHTTPConnection.__init__(self, host, port, verifycallback=verifycallback)
        self.secure = secure
        self.cookies = {}

    def connect(self):
        if self.secure:
            return super(WebConnection, self).connect()
        addrinfo = socket.getaddrinfo(self.host, self.port)[0]
        # workaround problems of too large mtu, moderately frequent occurance
        # in this space
        plainsock = socket.socket(addrinfo[0])
        plainsock.settimeout(self.mytimeout)
        try:
            plainsock.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1456)
        except socket.error:
            pass
        plainsock.connect(addrinfo[4])
        self.sock = plainsock
    
    def getresponse(self):
        try:
            rsp = super(WebConnection, self).getresponse()
            try:
                hdrs = [x.split(':', 1) for x in rsp.msg.headers]
            except AttributeError:
                hdrs = rsp.msg.items()
            for hdr in hdrs:
                if hdr[0] == 'Set-Cookie':
                    c = Cookie.BaseCookie(hdr[1])
                    for k in c:
                        self.cookies[k] = c[k].value
        except httplib.BadStatusLine:
            self.broken = True
            raise
        return rsp

    def request(self, method, url, body=None):
        headers = {}
        if body:
            headers['Content-Length'] = len(body)
        cookies = []
        for cookie in self.cookies:
            cookies.append('{0}={1}'.format(cookie, self.cookies[cookie]))
        headers['Cookie'] = ';'.join(cookies)
        headers['Host'] = 'pdu.cluster.net'
        headers['Accept'] = '*/*'
        headers['Accept-Language'] = 'en-US,en;q=0.9'
        headers['Connection'] = 'close'
        headers['Referer'] = 'http://pdu.cluster.net/setting_admin.htm'
        return super(WebConnection, self).request(method, url, body, headers)

    def grab_response(self, url, body=None, method=None):
        if method is None:
            method = 'GET' if body is None else 'POST'
        if body:
            self.request(method, url, body)
        else:
            self.request(method, url)
        rsp = self.getresponse()
        body = rsp.read()
        return body, rsp.status

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
        self._wc = WebConnection(target, secure=True, verifycallback=cv)
        return self._wc

    
def xml2stateinfo(statdata):
    statdata = fromstring(statdata)
    stateinfo = []
    sensornames = sorted([x.tag for x in statdata])
    themodel = None
    for model in sensorsbymodel:
        if sensorsbymodel[model] == sensornames:
            themodel = model
            break
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
def read_sensors(element, node, configmanager):
    category, name = element[-2:]
    justnames = False
    if len(element) == 3:
        # just get names
        category = name
        name = 'all'
        justnames = True
        for sensor in sensors:
            yield msg.ChildCollection(simplify_name(sensors[sensor][0]))
        return     
    if category in ('leds, fans'):
        return
    sn = _sensors_by_node.get(node, None)
    if not sn or sn[1] < time.time():
        cc = CoolteraClient(node, configmanager)
        cc.wc.request('GET', '/status.xml')
        rsp = cc.wc.getresponse()
        statdata = rsp.read()
        statinfo = xml2stateinfo(statdata)
        _sensors_by_node[node] = (statinfo, time.time() + 1)
        sn = _sensors_by_node.get(node, None)
    if sn:
        yield msg.SensorReadings(sn[0], name=node)


def retrieve(nodes, element, configmanager, inputdata):
    if element[0] == 'sensors':
        gp = greenpool.GreenPile(pdupool)
        for node in nodes:
            gp.spawn(read_sensors, element, node, configmanager)
        for rsp in gp:
            for datum in rsp:
                yield datum
        return
