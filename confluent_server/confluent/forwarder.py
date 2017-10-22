# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2017 Lenovo
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

#This handles port forwarding for web interfaces on management devices
#It will also hijack port 3900 and do best effort..

import eventlet
import eventlet.green.select as select
import eventlet.green.socket as socket
forwarders = {}
sockhandler = {}
allowedclients = set([])
vidtarget = None
vidforwarder = None

def handle_connection(incoming, outgoing):
    while True:
        r, _, _ = select.select((incoming, outgoing), (), (), 60)
        for mysock in r:
            data = mysock.recv(32768)
            if not data:
                return
            if mysock == incoming:
                outgoing.sendall(data)
            elif mysock == outgoing:
                incoming.sendall(data)


def forward_port(sock, target):
    while True:
        conn, cli = sock.accept()
        if cli[0] not in allowedclients:
            conn.close()
            continue
        try:
            client = socket.create_connection((target, 443))
        except Exception:
            conn.close()
            continue
        eventlet.spawn_n(handle_connection, conn, client)


def forward_video():
    sock = eventlet.listen(('::', 3900, 0, 0), family=socket.AF_INET6)
    while True:
        conn, cli = sock.accept()
        if cli[0] not in allowedclients:
            conn.close()
            continue
        if vidtarget is None:
            conn.close()
            continue
        try:
            vidclient = socket.create_connection((vidtarget, 3900))
        except Exception:
            conn.close()
            continue
        eventlet.spawn_n(handle_connection, conn, vidclient)

def get_port(addr, clientip):
    global vidtarget
    global vidforwarder
    if socket.getaddrinfo(clientip, 0)[0][0] == socket.AF_INET:
        allowedclients.add('::ffff:' + clientip)
    else:
        allowedclients.add(clientip)
    if addr not in forwarders:
        newsock = eventlet.listen(('::', 0, 0, 0),
                  family=socket.AF_INET6)
        forwarders[addr] = newsock
        sockhandler[newsock] = eventlet.spawn(forward_port, newsock, addr)
        if not vidforwarder:
            vidforwarder = eventlet.spawn(forward_video)
    vidtarget = addr
    return forwarders[addr].getsockname()[1]

