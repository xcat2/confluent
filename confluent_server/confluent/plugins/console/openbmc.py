# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2015-2019 Lenovo
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


# This plugin provides an ssh implementation comforming to the 'console'
# specification.  consoleserver or shellserver would be equally likely
# to use this.

import asyncio
import confluent.exceptions as cexc
import confluent.interface.console as conapi
import confluent.log as log
import confluent.tasks as tasks
import confluent.util as util
import aiohmi.exceptions as pygexc
import aiohmi.redfish.command as rcmd
import aiohmi.util.webclient as webclient
import aiohttp

class CustomVerifier(aiohttp.Fingerprint):
    def __init__(self, verifycallback):
        self._certverify = verifycallback

    def check(self, transport):
        sslobj = transport.get_extra_info("ssl_object")
        cert = sslobj.getpeercert(binary_form=True)
        if not self._certverify(cert):
            transport.close()
            raise pygexc.UnrecognizedCertificate('Unknown certificate',
                                                 cert)



def get_conn_params(node, configdata):
    if 'secret.hardwaremanagementuser' in configdata:
        username = configdata['secret.hardwaremanagementuser']['value']
    else:
        username = 'USERID'
    if 'secret.hardwaremanagementpassword' in configdata:
        passphrase = configdata['secret.hardwaremanagementpassword']['value']
    else:
        passphrase = 'PASSW0RD'  # for lack of a better guess
    if 'hardwaremanagement.manager' in configdata:
        bmc = configdata['hardwaremanagement.manager']['value']
    else:
        bmc = node
    bmc = bmc.split('/', 1)[0]
    return {
        'username': username,
        'passphrase': passphrase,
        'bmc': bmc,
    }
_configattributes = ('secret.hardwaremanagementuser',
                     'secret.hardwaremanagementpassword',
                     'hardwaremanagement.manager')
         



class OpenBmcConsole(conapi.Console):

    def __init__(self, node, config):
        self.node = node
        self.ws = None
        configdata = config.get_node_attributes([node], _configattributes, decrypt=True)
        connparams = get_conn_params(node, configdata[node])
        self.username = connparams['username']
        self.password = connparams['passphrase']
        self.bmc = connparams['bmc']
        self.origbmc = connparams['bmc']
        if ':' in self.bmc:
            self.bmc = '[{0}]'.format(self.bmc)
        self.datacallback = None
        self.nodeconfig = config
        self.connected = False
        self.recvr = None


    async def recvdata(self):
        try:
            while self.connected:
                pendingdata = await self.ws.receive()
                if pendingdata.type == aiohttp.WSMsgType.BINARY:
                    await self.datacallback(pendingdata.data)
                    continue
                elif pendingdata.type ==  aiohttp.WSMsgType.CLOSE:
                    await self.datacallback(conapi.ConsoleEvent.Disconnect)
                    return
                else:
                    print("Unknown response in WSConsoleHandler")
        except asyncio.CancelledError:
            pass


    async def connect(self, callback):
        self.datacallback = callback
        kv = util.TLSCertVerifier(
            self.nodeconfig, self.node, 'pubkeys.tls_hardwaremanager').verify_cert

        wc = webclient.WebConnection(self.origbmc, 443, verifycallback=kv)
        try:
            rsp = await wc.grab_json_response_with_status('/login', {'data': [self.username.decode('utf8'), self.password.decode("utf8")]}, headers={'Content-Type': 'application/json', 'Accept': 'application/json'})
        except Exception as e:
            raise cexc.TargetEndpointUnreachable(str(e))
        if rsp[1] > 400:
            raise cexc.TargetEndpointBadCredentials
        bmc = self.bmc
        if '%' in self.bmc:
            prefix = self.bmc.split('%')[0]
            bmc = prefix + ']'
        self.ssl = CustomVerifier(kv)
        self.clisess = aiohttp.ClientSession(cookie_jar=wc.cookies)
        protos = []
        for ck in wc.cookies:
            if ck.key == 'XSRF-TOKEN':
                protos = [ck.value]
        self.ws = await self.clisess.ws_connect('wss://{0}/console0'.format(self.bmc), protocols=protos, ssl=self.ssl)
    #self.ws.connect('wss://{0}/console0'.format(self.bmc), host=bmc, cookie='XSRF-TOKEN={0}; SESSION={1}'.format(wc.cookies['XSRF-TOKEN'], wc.cookies['SESSION']), subprotocols=[wc.cookies['XSRF-TOKEN']])
        self.connected = True
        self.recvr = tasks.spawn_task(self.recvdata())
        return

    async def write(self, data):
        await self.ws.send_str(data.decode())

    async def close(self):
        if self.recvr:
            self.recvr.cancel()
            self.recvr = None
        if self.ws:
            await self.ws.close()
        self.connected = False
        self.datacallback = None

async def create(nodes, element, configmanager, inputdata):
    if len(nodes) == 1:
        yield OpenBmcConsole(nodes[0], configmanager)
