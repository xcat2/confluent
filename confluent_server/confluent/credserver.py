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
import datetime
import eventlet
import eventlet.green.socket as socket
import eventlet.greenpool
import os

class CredServer(object):
    def __init__(self, bindhost='::', bindport=301, ttl=1):
        self.srv = socket.socket(socket.AF_INET6)
        self.srv.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind((bindhost, bindport))
        self.srv.listen(32)
        self.gpool = eventlet.greenpool.GreenPool(256)
        self.cfm = cfm.ConfigManager(None)
        self.runtime = eventlet.spawn(self.listen)

    def listen(self):
        while True:
            client, info = self.srv.accept()
            if info[1] > 1023:
                client.close()
                continue
            self.gpool.spawn_n(self.handle_client, client)
    
    def handle_client(self, client):
            client.send('\xc2\xd1-\xa8\x80\xd8j\xba')
            tlv = bytearray(client.recv(2))
            if tlv[0] != 1:
                client.close()
                return
            nodename = client.recv(tlv[1])
            tlv = bytearray(client.recv(2))
            apiarmed = self.cfm.get_node_attributes(nodename, 'api.armed')
            apiarmed = apiarmed.get(nodename, {}).get('api.armed', {}).get('value', None)
            if not apiarmed:
                client.close()
                return
            now = datetime.datetime.utcnow()
            expiry = datetime.datetime.strptime(apiarmed, "%Y-%m-%dT%H:%M:%SZ")
            if now > expiry:
                self.cfm.set_node_attributes({nodename: {'api.armed': ''}})
                client.close()
                return
            client.send(b'\x02\x20')
            rttoken = os.urandom(32)
            client.send(rttoken)
            client.send('\x00\x00')
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
            echotoken = client.recv(tlv[1])
            self.cfm.set_node_attributes({nodename: {'api.key': echotoken, 'api.armed': ''}})
            client.recv(2)  # drain end of message
            client.send('\x05\x00') # report success                
            client.close()

if __name__ == '__main__':
    a = CredServer()
    while True:
        eventlet.sleep(86400)

            
            
            
