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

# Documented somewhat at
# http://buildingskb.schneider-electric.com/view.php?AID=15197

# Here is the payload of an SSDP 'announce', sent to the multicast v4/v6 1900
# NOTIFY * HTTP/1.1
# HOST: 239.255.255.250:1900
# CACHE-CONTROL: max-age=1800
# AL: https://172.30.254.151:8080/redfish/v1
# SERVER: Linux/3.14.28-ltsi Redfish/1.0
# NT: urn:dmtf-org:service:redfish-rest:1
# USN: uuid:00000000-0000-0000-0005-000000000001::urn:dmtf-org:service:redfish-rest:1
# NTS: ssdp:alive


import confluent.neighutil as neighutil
import confluent.util as util
import confluent.log as log
import eventlet.green.select as select
import eventlet.green.socket as socket
import struct
import traceback

mcastv4addr = '239.255.255.250'
mcastv6addr = 'ff02::c'

ssdp6mcast = socket.inet_pton(socket.AF_INET6, mcastv6addr)
smsg = ('M-SEARCH * HTTP/1.1\r\n'
        'HOST: {0}:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        'ST: {1}\r\n'
        'MX: 3\r\n\r\n')


def scan(services, target=None):
    for service in services:
        for rply in _find_service(service, target):
            yield rply


def snoop(handler, byehandler=None, protocol=None, uuidlookup=None):
    """Watch for SSDP notify messages

    The handler shall be called on any service coming online.
    byehandler is called whenever a system advertises that it is departing.
    If no byehandler is specified, byebye messages are ignored.  The handler is
    given (as possible), the mac address, a list of viable sockaddrs to reference
    the peer, and the notification type (e.g.
    'urn:dmtf-org:service:redfish-rest:1'

    :param handler:  A handler for online notifications from network
    :param byehandler: Optional handler for devices going off the network
    """
    # Normally, I like using v6/v4 agnostic socket. However, since we are
    # dabbling in multicast wizardry here, such sockets can cause big problems,
    # so we will have two distinct sockets
    tracelog = log.Logger('trace')
    known_peers = set([])
    net6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    net6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    for ifidx in util.list_interface_indexes():
        v6grp = ssdp6mcast + struct.pack('=I', ifidx)
        net6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, v6grp)
    net6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    net4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for i4 in util.list_ips():
        ssdp4mcast = socket.inet_pton(socket.AF_INET, mcastv4addr) + \
                     socket.inet_aton(i4['addr'])
        net4.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                        ssdp4mcast)
    net4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    net4.bind(('', 1900))
    net6.bind(('', 1900))
    peerbymacaddress = {}
    while True:
        try:
            newmacs = set([])
            machandlers = {}
            r, _, _ = select.select((net4, net6), (), (), 60)
            neighutil.update_neigh()
            while r:
                for s in r:
                    (rsp, peer) = s.recvfrom(9000)
                    rsp = rsp.split('\r\n')
                    method, _, _ = rsp[0].split(' ', 2)
                    if method == 'NOTIFY':
                        ip = peer[0].partition('%')[0]
                        if ip not in neighutil.neightable:
                            continue
                        if peer in known_peers:
                            continue
                        mac = neighutil.neightable[ip]
                        known_peers.add(peer)
                        newmacs.add(mac)
                        if mac in peerbymacaddress:
                            peerbymacaddress[mac]['peers'].append(peer)
                        else:
                            peerbymacaddress[mac] = {
                                'hwaddr': mac,
                                'peers': [peer],
                            }
                            peerdata = peerbymacaddress[mac]
                            for headline in rsp[1:]:
                                if not headline:
                                    continue
                                header, _, value = headline.partition(':')
                                header = header.strip()
                                value = value.strip()
                                if header == 'NT':
                                    peerdata['service'] = value
                                elif header == 'NTS':
                                    if value == 'ssdp:byebye':
                                        machandlers[mac] = byehandler
                                    elif value == 'ssdp:alive':
                                        machandlers[mac] = None # handler
                    elif method == 'M-SEARCH':
                        if not uuidlookup:
                            continue
                        #ip = peer[0].partition('%')[0]
                        for headline in rsp[1:]:
                            if not headline:
                                continue
                            headline = headline.partition(':')
                            if len(headline) < 3:
                                continue
                            if  headline[0] == 'ST' and headline[-1].startswith(' urn:xcat.org:service:confluent:'):
                                for query in headline[-1].split('/'):
                                    if query.startswith('uuid='):
                                        curruuid = query.split('=', 1)[1].lower()
                                        node = uuidlookup(curruuid)
                                        if not node:
                                            break
                                        reply = 'HTTP/1.1 200 OK\r\nNODENAME: {0}'.format(node)
                                        s.sendto(reply, peer)
                r, _, _ = select.select((net4, net6), (), (), 0.2)
            for mac in newmacs:
                thehandler = machandlers.get(mac, None)
                if thehandler:
                    thehandler(peerbymacaddress[mac])
        except Exception:
                tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                             event=log.Events.stacktrace)


def _find_service(service, target):
    net4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    net6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    net6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    if target:
        addrs = socket.getaddrinfo(target, 1900, 0, socket.SOCK_DGRAM)
        for addr in addrs:
            host = addr[4][0]
            if addr[0] == socket.AF_INET:
                net4.sendto(smsg.format(host, service), addr[4])
            elif addr[0] == socket.AF_INET6:
                host = '[{0}]'.format(host)
                net6.sendto(smsg.format(host, service), addr[4])
    else:
        net4.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for idx in util.list_interface_indexes():
            net6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF,
                            idx)
            try:
                net6.sendto(smsg.format('[{0}]'.format(mcastv6addr), service
                                        ), (mcastv6addr, 1900, 0, 0))
            except socket.error:
                # ignore interfaces without ipv6 multicast causing error
                pass
        for i4 in util.list_ips():
            if 'broadcast' not in i4:
                continue
            addr = i4['addr']
            bcast = i4['broadcast']
            net4.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                            socket.inet_aton(addr))
            net4.sendto(smsg.format(mcastv4addr, service),
                        (mcastv4addr, 1900))
            net4.sendto(smsg.format(bcast, service), (bcast, 1900))
    # SSDP by spec encourages responses to spread out over a 3 second interval
    # hence we must be a bit more patient
    deadline = util.monotonic_time() + 4
    r, _, _ = select.select((net4, net6), (), (), 4)
    peerdata = {}
    while r:
        for s in r:
            (rsp, peer) = s.recvfrom(9000)
            neighutil.refresh_neigh()
            _parse_ssdp(peer, rsp, peerdata)
        timeout = deadline - util.monotonic_time()
        if timeout < 0:
            timeout = 0
        r, _, _ = select.select((net4, net6), (), (), timeout)
    for nid in peerdata:
        yield peerdata[nid]


def _parse_ssdp(peer, rsp, peerdata):
    ip = peer[0].partition('%')[0]
    nid = ip
    mac = None
    if ip in neighutil.neightable:
        nid = neighutil.neightable[ip]
        mac = nid
    headlines = rsp.split('\r\n')
    try:
        _, code, _ = headlines[0].split(' ', 2)
    except ValueError:
        return
    if code == '200':
        if nid in peerdata:
            peerdatum = peerdata[nid]
            if peer not in peerdatum['peers']:
                peerdatum['peers'].append(peer)
        else:
            peerdatum = {
                'peers': [peer],
                'hwaddr': mac,
            }
            peerdata[nid] = peerdatum
        for headline in headlines[1:]:
            if not headline:
                continue
            header, _, value = headline.partition(':')
            header = header.strip()
            value = value.strip()
            if header == 'AL' or header == 'LOCATION':
                if 'urls' not in peerdatum:
                    peerdatum['urls'] = [value]
                elif value not in peerdatum['urls']:
                    peerdatum['urls'].append(value)
            elif header == 'ST':
                if 'services' not in peerdatum:
                    peerdatum['services'] = [value]
                elif value not in peerdatum['services']:
                    peerdatum['services'].append(value)



if __name__ == '__main__':

    for rsp in scan(['urn:dmtf-org:service:redfish-rest:1']):
        print(repr(rsp))
    def fun(a):
        print(repr(a))
    def byefun(a):
        print('bye' + repr(a))
    snoop(fun, byefun)
