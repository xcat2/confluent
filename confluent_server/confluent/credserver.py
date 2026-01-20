# vim: tabstop=4 shiftwidth=4 softtabstop=4

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

import asyncio
import confluent.config.configmanager as cfm
import confluent.netutil as netutil
import confluent.util as util
import datetime
import hashlib
import hmac
import os
import struct
import ctypes
import ctypes.util

libc = ctypes.CDLL(ctypes.util.find_library('c'))

# cred grant tlvs:
# 0, 0 - null
# 1, len, <nodename>
# 2, len, token - echo request
# 3, len, token - echo reply
# 4, len, crypted - crypted apikey
# 5, 0, accept key
# 6, len, hmac - hmac of crypted key using shared secret for long-haul support
# 128, len, len, key - sealed key


def address_is_somewhat_trusted(address, nodename, cfm):
    if netutil.ip_on_same_subnet(address.split('%')[0], 'fe80::', 64):
        return True
    if netutil.address_is_local(address):
        return True
    authnets = cfm.get_node_attributes(nodename, 'trusted.subnets')
    authnets = authnets.get(nodename, {}).get('trusted.subnets', {}).get('value', None)
    if authnets:
        for authnet in authnets.split(','):
            for anet in authnet.split():
                na, plen = anet.split('/')
                plen = int(plen)
                if netutil.ip_on_same_subnet(address, na, plen):
                    return True
    return False

class CredServer(object):
    def __init__(self):
        self.cfm = cfm.ConfigManager(None)

    async def handle_client(self, client, peer):
        disarm = None
        try:
            apiarmed = None
            hmackey = None
            hmacval = None
            cloop = asyncio.get_event_loop()
            await cloop.sock_sendall(client, b'\xc2\xd1-\xa8\x80\xd8j\xba')
            tlv = bytearray(await cloop.sock_recv(client, 2))
            if tlv[0] != 1:
                client.close()
                return
            nodename = util.stringify(await cloop.sock_recv(client, tlv[1]))
            tlv = bytearray(await cloop.sock_recv(client, 2))  # should always be null
            onlylocal = True
            if tlv[0] == 6:
                hmacval = await cloop.sock_recv(client, tlv[1])
                hmackey = self.cfm.get_node_attributes(nodename, ['secret.selfapiarmtoken'], decrypt=True)
                hmackey = hmackey.get(nodename, {}).get('secret.selfapiarmtoken', {}).get('value', None)
            elif tlv[1]:
                await cloop.sock_recv(client, tlv[1])
            apimats = self.cfm.get_node_attributes(nodename,
                    ['deployment.apiarmed', 'deployment.sealedapikey'])
            apiarmed = apimats.get(nodename, {}).get('deployment.apiarmed', {}).get(
                    'value', None)
            if not hmackey:
                if not address_is_somewhat_trusted(peer[0], nodename, self.cfm):
                    client.close()
                    return
                if not apiarmed:
                    if apimats.get(nodename, {}).get(
                        'deployment.sealedapikey', {}).get('value', None):
                        sealed = apimats[nodename]['deployment.sealedapikey'][
                            'value']
                        if not isinstance(sealed, bytes):
                            sealed = sealed.encode('utf8')
                        reply = b'\x80' + struct.pack('>H', len(sealed) + 1) + sealed + b'\x00'
                        await cloop.sock_sendall(client, reply)
                    client.close()
                    return
                if apiarmed not in ('once', 'continuous'):
                    now = datetime.datetime.utcnow()
                    expiry = datetime.datetime.strptime(apiarmed, "%Y-%m-%dT%H:%M:%SZ")
                    if now > expiry:
                        self.cfm.set_node_attributes({nodename: {'deployment.apiarmed': ''}})
                        client.close()
                        return
            await cloop.sock_sendall(client, b'\x02\x20')
            rttoken = os.urandom(32)
            await cloop.sock_sendall(client, rttoken)
            await cloop.sock_sendall(client, b'\x00\x00')
            tlv = bytearray(await cloop.sock_recv(client, 2))
            if tlv[0] != 3:
                client.close()
                return
            echotoken = await cloop.sock_recv(client, tlv[1])
            if echotoken != rttoken:
                client.close()
                return
            tlv = bytearray(await cloop.sock_recv(client, 2))
            if tlv[0] != 4:
                client.close()
                return
            echotoken = util.stringify(await cloop.sock_recv(client, tlv[1]))
            if hmackey:
                etok = echotoken.encode('utf8')
                if hmacval != hmac.new(hmackey, etok, hashlib.sha256).digest():
                    client.close()
                    return
            cfgupdate = {nodename: {'crypted.selfapikey': {'hashvalue': echotoken}}}
            await self.cfm.set_node_attributes(cfgupdate)
            await cloop.sock_recv(client, 2)  # drain end of message
            await cloop.sock_sendall(client, b'\x05\x00') # report success
            if hmackey and apiarmed != 'continuous':
                self.cfm.clear_node_attributes([nodename], ['secret.selfapiarmtoken'])
            if apiarmed != 'continuous':
                disarm = {nodename: {'deployment.sealedapikey': '', 'deployment.apiarmed': ''}}
        finally:
            try:
                client.close()
            except Exception:
                pass
            if disarm:
                await self.cfm.set_node_attributes(disarm)


async def main():
    a = CredServer()
    while True:
        await asyncio.sleep(86400)
if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
