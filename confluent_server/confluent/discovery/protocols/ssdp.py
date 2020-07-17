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


import confluent.config.configmanager as cfm
import confluent.neighutil as neighutil
import confluent.util as util
import confluent.log as log
import confluent.netutil as netutil
import eventlet.green.select as select
import eventlet.green.socket as socket
import time
try:
    from eventlet.green.urllib.request import urlopen
except (ImportError, AssertionError):
    from eventlet.green.urllib2 import urlopen
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


def active_scan(handler, protocol=None):
    known_peers = set([])
    for scanned in scan(['urn:dmtf-org:service:redfish-rest:1']):
        for addr in scanned['addresses']:
            ip = addr[0].partition('%')[0]  # discard scope if present
            if ip not in neighutil.neightable:
                continue
            if addr in known_peers:
                break
            known_peers.add(addr)
        else:
            scanned['protocol'] = protocol
            handler(scanned)

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
        try:
            net4.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                            ssdp4mcast)
        except socket.error as e:
            if e.errno != 98:
                # errno 98 can happen if aliased, skip for now
                raise
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
                    if rsp[:4] == b'PING':
                        continue
                    rsp = rsp.split(b'\r\n')
                    method, _, _ = rsp[0].split(b' ', 2)
                    if method == b'NOTIFY':
                        ip = peer[0].partition('%')[0]
                        if ip not in neighutil.neightable:
                            continue
                        if peer in known_peers:
                            continue
                        mac = neighutil.neightable[ip]
                        known_peers.add(peer)
                        newmacs.add(mac)
                        if mac in peerbymacaddress:
                            peerbymacaddress[mac]['addresses'].append(peer)
                        else:
                            peerbymacaddress[mac] = {
                                'hwaddr': mac,
                                'addresses': [peer],
                            }
                            peerdata = peerbymacaddress[mac]
                            for headline in rsp[1:]:
                                if not headline:
                                    continue
                                headline = util.stringify(headline)
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
                    elif method == b'M-SEARCH':
                        if not uuidlookup:
                            continue
                        #ip = peer[0].partition('%')[0]
                        for headline in rsp[1:]:
                            if not headline:
                                continue
                            headline = util.stringify(headline)
                            headline = headline.partition(':')
                            if len(headline) < 3:
                                continue
                            if  headline[0] == 'ST' and headline[-1].startswith(' urn:xcat.org:service:confluent:'):
                                try:
                                    cfm.check_quorum()
                                except Exception:
                                    continue
                                for query in headline[-1].split('/'):
                                    if query.startswith('uuid='):
                                        curruuid = query.split('=', 1)[1].lower()
                                        node = uuidlookup(curruuid)
                                        if not node:
                                            break
                                        # Do not bother replying to a node that
                                        # we have no deployment activity
                                        # planned for
                                        cfg = cfm.ConfigManager(None)
                                        cfd = cfg.get_node_attributes(
                                            node, 'deployment.pendingprofile')
                                        if not cfd.get(node, {}).get(
                                                'deployment.pendingprofile', {}).get('value', None):
                                            break
                                        currtime = time.time()
                                        seconds = int(currtime)
                                        msecs = int(currtime * 1000 % 1000)
                                        reply = 'HTTP/1.1 200 OK\r\nNODENAME: {0}\r\nCURRTIME: {1}\r\nCURRMSECS: {2}\r\n'.format(node, seconds, msecs)
                                        if '%' in peer[0]:
                                            iface = peer[0].split('%', 1)[1]
                                            reply += 'MGTIFACE: {0}\r\n'.format(
                                                peer[0].split('%', 1)[1])
                                            ncfg = netutil.get_nic_config(
                                                cfg, node, ifidx=iface)
                                            if ncfg.get('matchesnodename', None):
                                                reply += 'DEFAULTNET: 1\r\n'
                                        if not isinstance(reply, bytes):
                                            reply = reply.encode('utf8')
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
                msg = smsg.format(host, service)
                if not isinstance(msg, bytes):
                    msg = msg.encode('utf8')
                net4.sendto(msg, addr[4])
            elif addr[0] == socket.AF_INET6:
                host = '[{0}]'.format(host)
                msg = smsg.format(host, service)
                if not isinstance(msg, bytes):
                    msg = msg.encode('utf8')               
                net6.sendto(msg, addr[4])
    else:
        net4.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for idx in util.list_interface_indexes():
            net6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF,
                            idx)
            try:
                msg = smsg.format('[{0}]'.format(mcastv6addr), service)
                if not isinstance(msg, bytes):
                    msg = msg.encode('utf8')
                net6.sendto(msg, (mcastv6addr, 1900, 0, 0))
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
            msg = smsg.format(mcastv4addr, service)
            if not isinstance(msg, bytes):
                msg = msg.encode('utf8')
            net4.sendto(msg, (mcastv4addr, 1900))
            msg = smsg.format(bcast, service)
            if not isinstance(msg, bytes):
                msg = msg.encode('utf8')
            net4.sendto(msg, (bcast, 1900))
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
        for url in peerdata[nid].get('urls', ()):
            if url.endswith('/desc.tmpl'):
                info = urlopen(url).read()
                if b'<friendlyName>Athena</friendlyName>' in info:
                    peerdata[nid]['services'] = ['service:thinkagile-storage']
                    yield peerdata[nid]


def _parse_ssdp(peer, rsp, peerdata):
    ip = peer[0].partition('%')[0]
    nid = ip
    mac = None
    if ip in neighutil.neightable:
        nid = neighutil.neightable[ip]
        mac = nid
    headlines = rsp.split(b'\r\n')
    try:
        _, code, _ = headlines[0].split(b' ', 2)
    except ValueError:
        return
    if code == b'200':
        if nid in peerdata:
            peerdatum = peerdata[nid]
            if peer not in peerdatum['addresses']:
                peerdatum['addresses'].append(peer)
        else:
            peerdatum = {
                'addresses': [peer],
                'hwaddr': mac,
            }
            peerdata[nid] = peerdatum
        for headline in headlines[1:]:
            if not headline:
                continue
            header, _, value = headline.partition(b':')
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
