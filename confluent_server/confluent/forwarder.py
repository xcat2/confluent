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
forwardersbyclient = {}
relaysbysession = {}
sessionsbyip = {}
ipsbysession = {}
sockhandler = {}
vidtargetbypeer = {}
vidforwarder = None

def handle_connection(incoming, outgoing):
    while True:
        r, _, _ = select.select((incoming, outgoing), (), (), 60)
        for mysock in r:
            data = mysock.recv(32768)
            if not data:
                incoming.close()
                outgoing.close()
                return
            if mysock == incoming:
                outgoing.sendall(data)
            elif mysock == outgoing:
                incoming.sendall(data)


def forward_port(sock, target, clientip, sessionid):
    while True:
        conn, cli = sock.accept()
        if cli[0] != clientip:
            conn.close()
            continue
        try:
            client = socket.create_connection((target, 443))
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1456)
        except Exception:
            conn.close()
            continue
        if sessionid not in relaysbysession:
            relaysbysession[sessionid] = {}
        relaysbysession[sessionid][eventlet.spawn(
            handle_connection, conn, client)] = conn


def forward_video():
    sock = eventlet.listen(('::', 3900, 0, 0), family=socket.AF_INET6)
    while True:
        conn, cli = sock.accept()
        if cli[0] not in vidtargetbypeer or not sessionsbyip.get(cli[0], None):
            conn.close()
            continue
        try:
            vidclient = socket.create_connection((vidtargetbypeer[cli[0]],
                                                  3900))
            vidclient.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, 1456)
        except Exception:
            conn.close()
            vidclient.close()
            continue
        eventlet.spawn_n(handle_connection, conn, vidclient)


def close_session(sessionid):
    for addr in forwardersbyclient.get(sessionid, []):
        killsock = forwardersbyclient[sessionid][addr]
        sockhandler[killsock].kill()
        del sockhandler[killsock]
        killsock.close()
    if sessionid in forwardersbyclient:
        del forwardersbyclient[sessionid]
    for clip in ipsbysession.get(sessionid, ()):
        sessionsbyip[clip].discard(sessionid)
    if sessionid in ipsbysession:
        del ipsbysession[sessionid]
    for relay in list(relaysbysession.get(sessionid, ())):
        conn = relaysbysession[sessionid][relay]
        relay.kill()
        conn.close()
    if sessionid in relaysbysession:
        del relaysbysession[sessionid]


def get_port(addr, clientip, sessionid):
    global vidforwarder
    if socket.getaddrinfo(clientip, 0)[0][0] == socket.AF_INET:
        clientip = '::ffff:' + clientip
    if sessionid not in ipsbysession:
        ipsbysession[sessionid] = set([])
    if clientip not in sessionsbyip:
        sessionsbyip[clientip] = set([])
    sessionsbyip[clientip].add(sessionid)
    ipsbysession[sessionid].add(clientip)
    if sessionid not in forwardersbyclient:
        forwardersbyclient[sessionid] = {}
    if addr not in forwardersbyclient[sessionid]:
        newsock = socket.socket(socket.AF_INET6)
        newport = 3901
        while newport:
            try:
                newsock.bind(('::', newport, 0, 0))
                newsock.listen(50)
                break
            except (socket.error, OSError) as e:
                if e.errno == 98:
                    newport += 1
                    continue
        forwardersbyclient[sessionid][addr] = newsock
        sockhandler[newsock] = eventlet.spawn(forward_port, newsock, addr,
                                              clientip, sessionid)
        if not vidforwarder:
            vidforwarder = eventlet.spawn(forward_video)
    vidtargetbypeer[clientip] = addr
    return forwardersbyclient[sessionid][addr].getsockname()[1]

