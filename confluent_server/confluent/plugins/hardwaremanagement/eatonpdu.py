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

import base64
import confluent.util as util
import confluent.messages as msg
import confluent.exceptions as exc
import eventlet
import eventlet.green.socket as socket

import aiohmi.util.webclient as wc
import confluent.util as util
import re
import hashlib
import json
import time


def simplify_name(name):
    return name.lower().replace(' ', '_').replace('/', '-').replace(
        '_-_', '-')

#eaton uses 'eval' rather than json, massage it to be valid json
def sanitize_json(data):
    if not isinstance(data, str):
        data = data.decode('utf8')
    return re.sub(r'([^ {:,]*):', r'"\1":', data).replace("'", '"').replace(',,', ',null,')


def answer_challenge(username, password, data):
    realm = data[0]
    nonce = data[1].encode('utf8')
    cnonce = data[2].encode('utf8')
    uri = data[3].encode('utf8')
    operation = data[4].encode('utf8')
    incvalue = '{:08d}'.format(int(data[5])).encode('utf8')
    a1 = hashlib.md5(':'.join([username, realm, password]).encode('utf8')).digest()
    a1 = b':'.join([a1, nonce, cnonce])
    skey = hashlib.md5(a1).hexdigest().encode('utf8')
    ac2 = b'AUTHENTICATE:' + uri
    s2c = hashlib.md5(ac2).hexdigest().encode('utf8')
    rsp = hashlib.md5(b':'.join([skey, nonce, incvalue, cnonce, operation, s2c])).hexdigest().encode('utf8')
    a2server = b':' + uri
    s2server = hashlib.md5(a2server).hexdigest().encode('utf8')
    s2rsp = hashlib.md5(b':'.join([skey, nonce, incvalue, cnonce, operation, s2server])).hexdigest().encode('utf8')
    return {'sessionKey': skey.decode('utf8'), 'szResponse': rsp.decode('utf8'), 'szResponseValue': s2rsp.decode('utf8')}

try:
    import Cookie
    httplib = eventlet.import_patched('httplib')
except ImportError:
    httplib = eventlet.import_patched('http.client')
    import http.cookies as Cookie

# Delta PDU webserver always closes connection,
# replace conditionals with always close
class WebResponse(httplib.HTTPResponse):
    def _check_close(self):
        return True

class WebConnection(wc.WebConnection):
    response_class = WebResponse
    def __init__(self, host, secure, verifycallback):
        if secure:
            port = 443
        else:
            port = 80
        wc.WebConnection.__init__(self, host, port, verifycallback=verifycallback)
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

_sensors_by_node = {}
def get_sensor_data(element, node, configmanager):
    category, name = element[-2:]
    justnames = False
    readings = []
    if len(element) == 3:
        # just get names
        category = name
        name = 'all'
        justnames = True
    if category in ('leds, fans', 'temperature'):
        return
    sn = _sensors_by_node.get(node, None)
    if not sn or sn[1] < time.time():
        gc = PDUClient(node, configmanager)
        try:
            sdata = gc.get_sensor_data()
        finally:
            gc.logout()
        _sensors_by_node[node] = [sdata, time.time() + 1]
        sn = _sensors_by_node.get(node, None)
    for outlet in sn[0]:
        for sensename in sn[0][outlet]:
            myname = 'Outlet {0} {1}'.format(outlet, sensename)
            measurement = sn[0][outlet][sensename]
            if name == 'all' or simplify_name(myname) == name:
                readings.append({
                    'name': myname,
                    'value': float(measurement['value']),
                    'units': measurement['units'],
                    'type': measurement['type'],
                })
    if justnames:
        for reading in readings:
            yield msg.ChildCollection(simplify_name(reading['name']))
    else:
        yield msg.SensorReadings(readings, name=node)


class PDUClient(object):
    def __init__(self, pdu, configmanager):
        self.node = pdu
        self.configmanager = configmanager
        self._token = None
        self._wc = None
        self.username = None
        self.sessid = None

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
        verifier = util.TLSCertVerifier(
            self.configmanager, self.node, 'pubkeys.tls_hardwaremanager')
        try:
            self._wc = WebConnection(target, secure=True, verifycallback=verifier.verify_cert)
            self.login(self.configmanager)
        except socket.error as e:
            pkey = self.configmanager.get_node_attributes(self.node, 'pubkeys.tls_hardwaremanager')
            pkey = pkey.get(self.node, {}).get('pubkeys.tls_hardwaremanager', {}).get('value', None)
            if pkey:
                raise
            self._wc = WebConnection(target, secure=False, verifycallback=verifier.verify_cert)
            self.login(self.configmanager)
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
        b64user = base64.b64encode(username.encode('utf8')).decode('utf8')
        b64pass = base64.b64encode(passwd.encode('utf8')).decode('utf8')
        rsp = self.wc.grab_response('/config/gateway?page=cgi_authentication&login={}&_dc={}'.format(b64user, int(time.time())))
        rsp = json.loads(sanitize_json(rsp[0]))
        self.sessid = rsp['data'][0]
        if rsp['data'][-1] == 'password':
            url = '/config/gateway?page=cgi_authenticationPassword&login={}&sessionId={}&password={}&dc={}'.format(
                b64user,
                rsp['data'][0],
                b64pass,
                int(time.time()),
            )
        else:
            parms = answer_challenge(username, passwd, rsp['data'][-1])
            url = '/config/gateway?page=cgi_authenticationChallenge&sessionId={}&login={}&sessionKey={}&szResponse={}&szResponseValue={}&dc={}'.format(
                rsp['data'][0],
                b64user,
                parms['sessionKey'],
                parms['szResponse'],
                parms['szResponseValue'],
                int(time.time()),
            )
        rsp = self.wc.grab_response(url)
        rsp = json.loads(sanitize_json(rsp[0]))
        if rsp['success'] != True:
            raise Exception('Failed to login to device')
        rsp = self.wc.grab_response('/config/gateway?page=cgi_checkUserSession&sessionId={}&_dc={}'.format(self.sessid, int(time.time())))

    def do_request(self, suburl):
        wc = self.wc
        url = '/config/gateway?page={}&sessionId={}&_dc={}'.format(suburl, self.sessid, int(time.time()))
        return wc.grab_response(url)

    def logout(self):
        self.do_request('cgi_logout')

    def get_outlet(self, outlet):
        rsp = self.do_request('cgi_pdu_outlets')
        data = sanitize_json(rsp[0])
        data = json.loads(data)
        data = data['data'][0]
        for outdata in data:
            outdata = outdata[0]
            if outdata[0] == outlet:
                return 'on' if outdata[3] else 'off'
        return
    
    def get_sensor_data(self):
        rsp = self.do_request('cgi_pdu_outlets')
        data = sanitize_json(rsp[0])
        data = json.loads(data)
        data = data['data'][0]
        sdata = {}
        for outdata in data:
            outsense = {}
            outletname = outdata[0][0]
            outsense['Energy'] = {
                'value': float(outdata[11] / 1000),
                'units': 'kwh',
                'type': 'Energy'
            }
            outsense['Power'] = {
                'value': float(outdata[4]),
                'units': 'w',
                'type': 'Power',
            }
            sdata[outletname] = outsense
        return sdata

    def set_outlet(self, outlet, state):
        rsp = self.do_request('cgi_pdu_outlets')
        data = sanitize_json(rsp[0])
        data = json.loads(data)
        data = data['data'][0]
        idx = 1
        for outdata in data:
            outdata = outdata[0]
            if outdata[0] == outlet:
                payload = "<SET_OBJECT><OBJECT name='PDU.OutletSystem.Outlet[{}].DelayBefore{}'>0</OBJECT>".format(idx, 'Startup' if state == 'on' else 'Shutdown')
                rsp = self.wc.grab_response('/config/set_object_mass.xml?sessionId={}'.format(self.sessid), payload)
                return
            idx += 1

def retrieve(nodes, element, configmanager, inputdata):
    if element[0] == 'sensors':
        for node in nodes:
            for res in get_sensor_data(element, node, configmanager):
                yield res
        return
    elif 'outlets' not in element:
        for node in nodes:
            yield  msg.ConfluentResourceUnavailable(node, 'Not implemented')
        return
    for node in nodes:
        gc = PDUClient(node, configmanager)
        try:
            state = gc.get_outlet(element[-1])
            yield msg.PowerState(node=node, state=state)
        finally:
            gc.logout()

def update(nodes, element, configmanager, inputdata):
    if 'outlets' not in element:
        yield msg.ConfluentResourceUnavailable(node, 'Not implemented')
        return
    for node in nodes:
        gc = PDUClient(node, configmanager)
        newstate = inputdata.powerstate(node)
        try:
            gc.set_outlet(element[-1], newstate)
        finally:
            gc.logout()
    eventlet.sleep(2)
    for res in retrieve(nodes, element, configmanager, inputdata):
        yield res
