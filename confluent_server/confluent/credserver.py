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

import confluent.config.configmanager as cfm
import confluent.netutil as netutil
import confluent.util as util
import datetime
import eventlet
import eventlet.green.select as select
import eventlet.green.socket as socket
import eventlet.greenpool
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

    def handle_client(self, client, peer):
        try:
            apiarmed = None
            hmackey = None
            hmacval = None
            client.send(b'\xc2\xd1-\xa8\x80\xd8j\xba')
            tlv = bytearray(client.recv(2))
            if tlv[0] != 1:
                client.close()
                return
            nodename = util.stringify(client.recv(tlv[1]))
            tlv = bytearray(client.recv(2))  # should always be null
            onlylocal = True
            if tlv[0] == 6:
                hmacval = client.recv(tlv[1])
                hmackey = self.cfm.get_node_attributes(nodename, ['secret.selfapiarmtoken'], decrypt=True)
                hmackey = hmackey.get(nodename, {}).get('secret.selfapiarmtoken', {}).get('value', None)
            elif tlv[1]:
                client.recv(tlv[1])
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
                        client.send(reply)
                    client.close()
                    return
                if apiarmed not in ('once', 'continuous'):
                    now = datetime.datetime.utcnow()
                    expiry = datetime.datetime.strptime(apiarmed, "%Y-%m-%dT%H:%M:%SZ")
                    if now > expiry:
                        self.cfm.set_node_attributes({nodename: {'deployment.apiarmed': ''}})
                        client.close()
                        return
            client.send(b'\x02\x20')
            rttoken = os.urandom(32)
            client.send(rttoken)
            client.send(b'\x00\x00')
            tlv = bytearray(client.recv(2))
            if tlv[0] != 3:
                client.close()
                return
            echotoken = client.recv(tlv[1])
            if echotoken != rttoken:
                client.close()
                return
            tlv = bytearray(client.recv(2))
            if tlv[0] != 4:
                client.close()
                return
            echotoken = util.stringify(client.recv(tlv[1]))
            if hmackey:
                etok = echotoken.encode('utf8')
                if hmacval != hmac.new(hmackey, etok, hashlib.sha256).digest():
                    client.close()
                    return
            cfgupdate = {nodename: {'crypted.selfapikey': {'hashvalue': echotoken}}}
            self.cfm.set_node_attributes(cfgupdate)
            client.recv(2)  # drain end of message
            client.send(b'\x05\x00') # report success
            if hmackey and apiarmed != 'continuous':
                self.cfm.clear_node_attributes([nodename], ['secret.selfapiarmtoken'])
            if apiarmed != 'continuous':
                tokclear = {nodename: {'deployment.sealedapikey': '', 'deployment.apiarmed': ''}}
                self.cfm.set_node_attributes(tokclear)
        finally:
            client.close()

if __name__ == '__main__':
    a = CredServer()
    while True:
        eventlet.sleep(86400)
