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

import asyncio
import urllib.parse

import aiohmi.util.webclient as wc
import confluent.messages as msg
import confluent.exceptions as exc
import lxml.etree as etree

def fromstring(inputdata):
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
    if isinstance(inputdata, bytes):
        cmpstr = b'!entity'
    else:
        cmpstr = '!entity'
    if cmpstr in inputdata.lower():
        raise Exception('!ENTITY not supported in this interface')
    # The measures above should filter out the risky facets of xml
    # We don't need sophisticated feature support
    return etree.fromstring(inputdata, parser=parser)  # nosec


_fixedheaders = {
    'Host': 'pdu.cluster.net',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.9',
    'Connection': 'close',
    'Referer': 'http://pdu.cluster.net/setting_admin.htm',
}


class WebConnection(wc.WebConnection):
    def __init__(self, host):
        # port 80 makes webclient use plain http
        wc.WebConnection.__init__(self, host, 80)
        for header in _fixedheaders:
            self.set_header(header, _fixedheaders[header])

    async def grab_response(self, url, body=None, method=None):
        rsp, status, _ = await self.grab_response_with_status(
            url, body, method=method)
        return rsp, status


class PDUClient(object):
    def __init__(self, pdu, configmanager):
        self.node = pdu
        self.configmanager = configmanager
        self._outletmap = {}
        self.wc = None
        self.connectlock = asyncio.Lock()

    async def connect(self):
        async with self.connectlock:
            if self.wc:
                return self.wc
            targcfg = self.configmanager.get_node_attributes(self.node,
                                                ['hardwaremanagement.manager'],
                                                decrypt=True)
            targcfg = targcfg.get(self.node, {})
            target = targcfg.get(
                'hardwaremanagement.manager', {}).get('value', None)
            if not target:
                target = self.node
            target = target.split('/', 1)[0]
            self.wc = WebConnection(target)
            try:
                await self.login(self.configmanager)
            except Exception:
                self.wc = None
                raise
            return self.wc

    async def map_outlets(self):
        if not self._outletmap:
            await self.connect()
            rsp, status = await self.wc.grab_response('/setting_admin.htm')
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

    async def login(self, configmanager):
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
        body = urllib.parse.urlencode({
            'User': username,
            'Password': passwd,
            'B1': 'Login',
        })
        rsp = await self.wc.grab_response('/login.htm', body)
        if b'Incorrect User Name' in rsp[0]:
            raise exc.TargetEndpointBadCredentials()

    async def logout(self):
        async with self.connectlock:
            if self.wc:
                await self.wc.grab_response('/logout_wait.htm')
                self.wc = None

    async def get_outlet(self, outlet):
        await self.connect()
        rsp = await self.wc.grab_response('/setting_admin4.xml')
        xd = fromstring(rsp[0])
        for ch in xd:
            if 'relay' not in ch.tag:
                continue
            outnum = ch.tag.split('relay')[-1]
            if outnum == outlet:
                return ch.text.lower()

    async def set_outlet(self, outlet, state):
        state = 0 if state == 'off' else 1
        outlet = int(outlet)
        outletmap = await self.map_outlets()
        ident = outletmap[outlet]
        sitem = '/SetParm?item={}?content={}'.format(ident, state)
        await self.connect()
        await self.wc.grab_response(sitem)

async def retrieve(nodes, element, configmanager, inputdata):
    if 'outlets' not in element:
        for node in nodes:
            yield  msg.ConfluentResourceUnavailable(node, 'Not implemented')
        return
    for node in nodes:
        try:
            gc = PDUClient(node, configmanager)
            state = await gc.get_outlet(element[-1])
        except exc.TargetEndpointBadCredentials:
            yield msg.ConfluentTargetInvalidCredentials(node)
            continue
        yield msg.PowerState(node=node, state=state)
        await gc.logout()

async def update(nodes, element, configmanager, inputdata):
    if 'outlets' not in element:
        for node in nodes:
            yield msg.ConfluentResourceUnavailable(node, 'Not implemented')
        return
    timeout = 4
    for node in nodes:
        gc = PDUClient(node, configmanager)
        newstate = inputdata.powerstate(node)
        await gc.set_outlet(element[-1], newstate)
        await gc.logout()
    await asyncio.sleep(timeout)
    async for res in retrieve(nodes, element, configmanager, inputdata):
        yield res
