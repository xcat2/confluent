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

import confluent.util as util
import confluent.messages as msg
import confluent.exceptions as exc
import eventlet
from xml.etree.ElementTree import fromstring as rfromstring

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

class WebConnection(httplib.HTTPConnection):
    response_class = WebResponse
    def __init__(self, host):
        httplib.HTTPConnection.__init__(self, host, 80)
        self.cookies = {}

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



class PDUClient(object):
    def __init__(self, pdu, configmanager):
        self.node = pdu
        self.configmanager = configmanager
        self._outletmap = {}
        self._token = None
        self._wc = None
        self.username = None

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
        self._wc = WebConnection(target)
        self.login(self.configmanager)
        return self._wc

    @property
    def map_outlets(self):
        if not self._outletmap:
            rsp, status = self.wc.grab_response('/setting_admin.htm')
            if not isinstance(rsp, str):
                rsp = rsp.decode('utf8')
            for line in rsp.split('\n'):
                if 'ibmsys_info_relay' in line and 'onClick="set(' in line:
                    line = line.partition('onClick="set(\'')[-1]
                    ident, label = line.split(',')[:2]
                    ident = ident.replace('\'', '')
                    label = label.replace('\'', '')
                    label = label.replace('ibmsys_info_relay', '')
                    idx = int(label)
                    self._outletmap[idx] = ident
        return self._outletmap


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
        body = 'User={0}&Password={1}&B1=Login'.format(username, passwd)
        rsp = self.wc.grab_response('/login.htm', body)
        if b'Incorrect User Name' in rsp[0]:
            raise exc.TargetEndpointBadCredentials()


    def logout(self):
        self.wc.grab_response('/logout_wait.htm')

    def get_outlet(self, outlet):
        rsp = self.wc.grab_response('/setting_admin4.xml')
        xd = fromstring(rsp[0])
        for ch in xd:
            if 'relay' not in ch.tag:
                continue
            outnum = ch.tag.split('relay')[-1]
            if outnum == outlet:
                return ch.text.lower()

    def set_outlet(self, outlet, state):
        state = 0 if state == 'off' else 1
        outlet = int(outlet)
        ident = self.map_outlets[outlet]
        sitem = '/SetParm?item={}?content={}'.format(ident, state)
        self.wc.grab_response(sitem)

def retrieve(nodes, element, configmanager, inputdata):
    if 'outlets' not in element:
        for node in nodes:
            yield  msg.ConfluentResourceUnavailable(node, 'Not implemented')
        return
    for node in nodes:
        try:
            gc = PDUClient(node, configmanager)
            state = gc.get_outlet(element[-1])
        except exc.TargetEndpointBadCredentials:
            yield msg.ConfluentTargetInvalidCredentials(node)
            continue
        yield msg.PowerState(node=node, state=state)
        gc.logout()

def update(nodes, element, configmanager, inputdata):
    if 'outlets' not in element:
        yield msg.ConfluentResourceUnavailable(node, 'Not implemented')
        return
    timeout = 1
    for node in nodes:
        gc = PDUClient(node, configmanager)
        newstate = inputdata.powerstate(node)
        gc.set_outlet(element[-1], newstate)
        timeout += 1
        gc.logout()
    eventlet.sleep(timeout)
    for res in retrieve(nodes, element, configmanager, inputdata):
        yield res
