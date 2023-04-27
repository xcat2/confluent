# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2023 Lenovo
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
import confluent.collective.manager as collective
import confluent.neighutil as neighutil
import confluent.noderange as noderange
import confluent.util as util
import confluent.log as log
import confluent.netutil as netutil
import eventlet
import eventlet.green.select as select
import eventlet.green.socket as socket
import eventlet.greenpool as gp
import os
import time
import struct
import traceback

webclient = eventlet.import_patched('pyghmi.util.webclient')
mcastv4addr = '224.0.0.251'
mcastv6addr = 'ff02::fb'

mdns6mcast = socket.inet_pton(socket.AF_INET6, mcastv6addr)

def name_to_qname(name):
    nameparts = name.split('.')
    qname = b''
    for namepart in name.split('.'):
        namepart = namepart.encode('utf8')
        qname += bytes(bytearray([len(namepart)])) + namepart
    qname += b'\x00'
    return qname

PTR = 12
SRV = 33

def _makequery(name):
    return struct.pack('!HHHHHH', 
            0, # transaction id
            0, # flags, stdard query
            1, # query count
            0, # answers
            0, # authorities
            0) + \
        name_to_qname(name) + \
        struct.pack('!HH', 
            PTR,
            (1 << 15) | 1)  # Unicast response

#listsrvs = _makequery('_services._dns-sd._udp.local')  # to get all possible services
listobmccons = _makequery('_obmc_console._tcp.local')


def _process_snoop(peer, rsp, mac, known_peers, newmacs, peerbymacaddress, byehandler, machandlers, handler):
    if mac in peerbymacaddress and peer not in peerbymacaddress[mac]['addresses']:
        peerbymacaddress[mac]['addresses'].append(peer)
    else:
        sdata = _mdns_to_dict(rsp)
        if not sdata:
            return 0
        peerdata = {
            'hwaddr': mac,
            'addresses': [peer],
            'services': ['openbmc'],
            'urls': '/redfish/v1/'
        }
        if sdata.get('ttl', 0) == 0:
            if byehandler:
                eventlet.spawn_n(check_fish_handler, byehandler, peerdata, known_peers, newmacs, peerbymacaddress, machandlers, mac, peer)
            return 1
        if handler:
            eventlet.spawn_n(check_fish_handler, handler, peerdata, known_peers, newmacs, peerbymacaddress, machandlers, mac, peer)
        return 2
        
def check_fish_handler(handler, peerdata, known_peers, newmacs, peerbymacaddress, machandlers, mac, peer):
    retdata = check_fish(('/redfish/v1/', peerdata))
    if retdata:
        known_peers.add(peer)
        newmacs.add(mac)
        peerbymacaddress[mac] = retdata
        machandlers[mac] = handler


def snoop(handler, byehandler=None, protocol=None, uuidlookup=None):
    """Watch for unsolicited mDNS answers

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
    # TTL=0 is a wthdrawal, otherwise an announce
    tracelog = log.Logger('trace')
    net4, net6 = get_sockets()
    net6.bind(('', 5353))
    net4.bind(('', 5353))
    try:
        active_scan(handler, protocol)
    except Exception as e:
        tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                    event=log.Events.stacktrace)
    known_peers = set([])
    recent_peers = set([])
    for ifidx in util.list_interface_indexes():
        v6grp = mdns6mcast + struct.pack('=I', ifidx)
        net6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, v6grp)
    for i4 in util.list_ips():
        mdns4mcast = socket.inet_pton(socket.AF_INET, mcastv4addr) + \
                     socket.inet_aton(i4['addr'])
        try:
            net4.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                            mdns4mcast)
        except socket.error as e:
            if e.errno != 98:
                # errno 98 can happen if aliased, skip for now
                raise
    peerbymacaddress = {}
    while True:
        try:
            newmacs = set([])
            deferrednotifies = []
            machandlers = {}
            r = select.select((net4, net6), (), (), 60)
            if r:
                r = r[0]
            recent_peers = set([])
            while r and len(deferrednotifies) < 256:
                for s in r:
                    (rsp, peer) = s.recvfrom(9000)
                    if peer in recent_peers:
                        continue
                    mac = neighutil.get_hwaddr(peer[0])
                    if not mac:
                        probepeer = (peer[0], struct.unpack('H', os.urandom(2))[0] | 1025) + peer[2:]
                        try:
                            s.sendto(b'\x00', probepeer)
                        except Exception:
                            continue
                        deferrednotifies.append((peer, rsp))
                    datum = _process_snoop(peer, rsp, mac, known_peers, newmacs, peerbymacaddress, byehandler, machandlers, handler)
                    if datum == 2:
                        recent_peers.add(peer)
                r = select.select((net4, net6), (), (), 1.5)
                if r:
                    r = r[0]
            if deferrednotifies:
                eventlet.sleep(2.2)
            for peerrsp in deferrednotifies:
                peer, rsp = peerrsp
                mac = neighutil.get_hwaddr(peer[0])
                if not mac:
                    continue
                _process_snoop(peer, rsp, mac, known_peers, newmacs, peerbymacaddress, byehandler, machandlers, handler)
            for mac in newmacs:
                thehandler = machandlers.get(mac, None)
                if thehandler:
                    thehandler(peerbymacaddress[mac])
        except Exception:
                tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                             event=log.Events.stacktrace)


def _get_svrip(peerdata):
    for addr in peerdata['addresses']:
        if addr[0].startswith('fe80::'):
            if '%' not in addr[0]:
                return addr[0] + '%{0}'.format(addr[3])
            return addr[0]
    return peerdata['addresses'][0][0]

def get_sockets():
    net6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    net6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    net6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    net4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    net4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    return net4, net6
        
def active_scan(handler, protocol=None):
    net4, net6 = get_sockets()
    for idx in util.list_interface_indexes():
        net6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF,
                        idx)
        try:
            net6.sendto(listobmccons, (mcastv6addr, 5353, 0, 0))
        except socket.error:
            # ignore interfaces without ipv6 multicast causing error
                pass
    for i4 in util.list_ips():
        if 'broadcast' not in i4:
            continue
        addr = i4['addr']
        net4.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                        socket.inet_aton(addr))
        try:
            net4.sendto(listobmccons, (mcastv4addr, 5353))
        except socket.error as se:
            if se.errno != 101 and se.errno != 1:
                raise
    deadline = util.monotonic_time() + 2
    r, _, _ = select.select((net4, net6), (), (), 2)
    peerdata = {}
    deferparse = []
    while r:
        for s in r:
            (rsp, peer) = s.recvfrom(9000)
            if not neighutil.get_hwaddr(peer[0]):
                probepeer = (peer[0], struct.unpack('H', os.urandom(2))[0] | 1025) + peer[2:]
                try:
                    s.sendto(b'\x00', probepeer)
                except Exception:
                    continue
                deferparse.append((rsp, peer))
                continue
            _parse_mdns(peer, rsp, peerdata, '_obmc_console._tcp.local')
        timeout = deadline - util.monotonic_time()
        if timeout < 0:
            timeout = 0
        r, _, _ = select.select((net4, net6), (), (), timeout)
    if deferparse:
        eventlet.sleep(2.2)
    for dp in deferparse:
        rsp, peer = dp
        _parse_mdns(peer, rsp, peerdata, '_obmc_console._tcp.local')
    querypool = gp.GreenPool()
    pooltargs = []
    for nid in peerdata:
        if '/redfish/v1/' not in peerdata[nid].get('urls', ()) and '/redfish/v1' not in peerdata[nid].get('urls', ()):
            continue
        pooltargs.append(('/redfish/v1/', peerdata[nid]))
        # For now, don't interrogate generic redfish bmcs
        # This is due to a need to deduplicate from some supported SLP
        # targets (IMM, TSM, others)
        # activate this else once the core filters/merges duplicate uuid
        # or we drop support for those devices
        #else:
        #    pooltargs.append(('/redfish/v1/', peerdata[nid]))
    for pi in querypool.imap(check_fish, pooltargs):
        if pi is not None:
            handler(pi)

def check_fish(urldata, port=443, verifycallback=None):
    if not verifycallback:
        verifycallback = lambda x: True
    url, data = urldata
    try:
        wc = webclient.SecureHTTPConnection(_get_svrip(data), port, verifycallback=verifycallback, timeout=1.5)
        peerinfo = wc.grab_json_response(url)
    except socket.error:
        return None
    if url == '/DeviceDescription.json':
        try:
            peerinfo = peerinfo[0]
            myuuid = peerinfo['node-uuid'].lower()
            if '-' not in myuuid:
                myuuid = '-'.join([myuuid[:8], myuuid[8:12], myuuid[12:16], myuuid[16:20], myuuid[20:]])
            data['uuid'] = myuuid
            data['attributes'] = peerinfo
            data['services'] = ['lenovo-xcc']
            return data
        except (IndexError, KeyError):
            return None
            url = '/redfish/v1/'
            peerinfo = wc.grab_json_response('/redfish/v1/')
    if url == '/redfish/v1/':
        if 'UUID' in peerinfo:
            if 'services' not in data:
                data['services'] = ['service:redfish-bmc']
            else:
                data['services'].append('service:redfish-bmc')
            data['uuid'] = peerinfo['UUID'].lower()
            return data
    return None

def extract_qname(view, reply):
    name = ''
    idx = 1
    if isinstance(view[0], int):
        currlen = view[0]
    else:
        currlen = ord(view[0])
    while currlen:
        if currlen == 192:
            name += extract_qname(reply[view[1]:], reply)[1] + '.'
            view = view[2:]
            idx += 1
            if name:
                return idx, name[:-1]
            return idx, ''
        else:
            name += view[1:currlen + 1].tobytes().decode('utf8') + '.'
            view = view[currlen + 1:]
            idx += currlen + 1
        if not view:
            break  # some contexts don't null terminate
        if isinstance(view[0], int):
            currlen = view[0]
        else:
            currlen = ord(view[0])
    if name:
        return idx, name[:-1]
    return idx, ''



def _mdns_to_dict(rsp):
    txid, flags, quests, answers, arr, morerr = struct.unpack('!HHHHHH', rsp[:12])
    rv = memoryview(rsp[12:])
    rspv = memoryview(rsp)
    retval = {}
    while quests:
        idx, name = extract_qname(rv, rspv)
        rv = rv[idx:]
        typ, dclass = struct.unpack('!HH', rv[:4]) 
        quests -= 1
        rv = rv[4:]
    while answers:
        idx, name = extract_qname(rv, rspv)
        rv = rv[idx:]
        typ, dclass, ttl, dlen = struct.unpack('!HHIH', rv[:10])
        if 0 and typ == 12:  # PTR, we don't need for now...
            adata = extract_qname(rv[10:], rspv)
            if 'ptrs' not in retval:
                retval['ptrs'] = [{'name': adata, 'ttl': ttl}]
            else:
                retval['ptrs'].append({'name': adata, 'ttl': ttl})
        if typ == 33:
            portnum = struct.unpack('!H', rv[14:16])[0]
            retval['protoname'] = name.split('.', 1)[1]
            retval['portnumber'] = portnum
            retval['ttl'] = ttl
        rv = rv[dlen + 10:]
        answers -= 1
    return retval


def _parse_mdns(peer, rsp, peerdata, srvname):
    parsed = _mdns_to_dict(rsp)
    if not parsed:
        return
    if parsed.get('ttl', 0) == 0:
        return
    nid = peer[0]
    mac = neighutil.get_hwaddr(peer[0])
    if mac:
        nid = mac
    if nid in peerdata:
        peerdatum = peerdata[nid]
        if peer not in peerdatum['addresses']:
            peerdatum['addresses'].append(peer)
    else:
        peerdatum = {
            'addresses': [peer],
            'hwaddr': mac,
            'services': [srvname]
        }
        if srvname == '_obmc_console._tcp.local':
            peerdatum['services'] = ['openbmc']
            peerdatum['urls'] = ['/redfish/v1/']
        peerdata[nid] = peerdatum
    

def _parse_ssdp(peer, rsp, peerdata):
    nid = peer[0]
    mac = None
    mac = neighutil.get_hwaddr(peer[0])
    if mac:
        nid = mac
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
            header = header.strip().decode('utf8')
            value = value.strip().decode('utf8')
            if header == 'AL' or header == 'LOCATION':
                value = value[value.index('://')+3:]
                value = value[value.index('/'):]
                if 'urls' not in peerdatum:
                    peerdatum['urls'] = [value]
                elif value not in peerdatum['urls']:
                    peerdatum['urls'].append(value)
            elif header == 'ST':
                if 'services' not in peerdatum:
                    peerdatum['services'] = [value]
                elif value not in peerdatum['services']:
                    peerdatum['services'].append(value)
            elif header == 'USN':
                peerdatum['usn'] = value
            elif header == 'MODELNAME':
                peerdatum['modelname'] = value


from pprint import pprint
if __name__ == '__main__':
    def printit(rsp):
        print(repr(rsp))
    snoop(pprint)
