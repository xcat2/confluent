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

import confluent.neighutil as neighutil
import confluent.util as util
import os
import random
import eventlet.green.select as select
import eventlet.green.socket as socket
import struct
import subprocess


_slp_services = set([
    'service:management-hardware.IBM:integrated-management-module2',
    'service:lenovo-smm',
    'service:management-hardware.Lenovo:lenovo-xclarity-controller',
])

# SLP has a lot of ambition that was unfulfilled in practice.
# So we have a static footer here to always use 'DEFAULT' scope, no LDAP
# predicates, and no authentication for service requests
srvreqfooter = b'\x00\x07DEFAULT\x00\x00\x00\x00'
# An empty instance of the attribute list extension
# which is defined in RFC 3059, used to indicate support for that capability
attrlistext = b'\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00'


def _parse_slp_header(packet):
    packet = bytearray(packet)
    if len(packet) < 16 or packet[0] != 2:
        # discard packets that are obviously useless
        return None
    parsed = {
        'function': packet[1],
    }
    (offset, parsed['xid'], langlen) = struct.unpack('!IHH',
                                           bytes(b'\x00' + packet[7:14]))
    parsed['lang'] = packet[14:14 + langlen].decode('utf-8')
    parsed['payload'] = packet[14 + langlen:]
    if offset:
        parsed['offset'] = 14 + langlen
        parsed['extoffset'] = offset
    return parsed


def _pop_url(payload):
    urllen = struct.unpack('!H', bytes(payload[3:5]))[0]
    url = bytes(payload[5:5+urllen]).decode('utf-8')
    if payload[5+urllen] != 0:
        raise Exception('Auth blocks unsupported')
    payload = payload[5+urllen+1:]
    return url, payload


def _parse_SrvRply(parsed):
    """ Modify passed dictionary to have parsed data


    :param parsed:
    :return:
    """
    payload = parsed['payload']
    ecode, ucount = struct.unpack('!HH', bytes(payload[0:4]))
    if ecode:
        parsed['errorcode'] = ecode
    payload = payload[4:]
    parsed['urls'] = []
    while ucount:
        ucount -= 1
        url, payload = _pop_url(payload)
        parsed['urls'].append(url)


def _parse_slp_packet(packet, peer, rsps, xidmap):
    parsed = _parse_slp_header(packet)
    if not parsed:
        return
    addr = peer[0]
    if '%' in addr:
        addr = addr[:addr.index('%')]
    mac = None
    if addr in neighutil.neightable:
        identifier = neighutil.neightable[addr]
        mac = identifier
    else:
        identifier = addr
    if (identifier, parsed['xid']) in rsps:
        # avoid obviously duplicate entries
        parsed = rsps[(identifier, parsed['xid'])]
    else:
        rsps[(identifier, parsed['xid'])] = parsed
    if mac and 'hwaddr' not in parsed:
        parsed['hwaddr'] = mac
    if parsed['xid'] in xidmap:
        parsed['services'] = [xidmap[parsed['xid']]]
    if 'addresses' in parsed:
        if peer not in parsed['addresses']:
            parsed['addresses'].append(peer)
    else:
        parsed['addresses'] = [peer]
    if parsed['function'] == 2:  # A service reply
        _parse_SrvRply(parsed)


def _v6mcasthash(srvtype):
    # The hash algorithm described by RFC 3111
    nums = bytearray(srvtype.encode('utf-8'))
    hashval = 0
    for i in nums:
        hashval *= 33
        hashval += i
        hashval &= 0xffff  # only need to track the lowest 16 bits
    hashval &= 0x3ff
    hashval |= 0x1000
    return '{0:x}'.format(hashval)


def _generate_slp_header(payload, multicast, functionid, xid, extoffset=0):
    if multicast:
        flags = 0x2000
    else:
        flags = 0
    packetlen = len(payload) + 16  # we have a fixed 16 byte header supported
    if extoffset:  # if we have an offset, add 16 to account for this function
        # generating a 16 byte header
        extoffset += 16
    if packetlen > 1400:
        # For now, we aren't intending to support large SLP transmits
        # raise an exception to help identify if such a requirement emerges
        raise Exception("TODO: Transmit overflow packets")
    # We always do SLP v2, and only v2
    header = bytearray([2, functionid])
    # SLP uses 24 bit packed integers, so in such places we pack 32 then
    # discard the high byte
    header.extend(struct.pack('!IH', packetlen, flags)[1:])
    # '2' below refers to the length of the language tag
    header.extend(struct.pack('!IHH', extoffset, xid, 2)[1:])
    # we only do english (in SLP world, it's not like non-english appears...)
    header.extend(b'en')
    return header

def _generate_attr_request(service, xid):
    service = service.encode('utf-8')
    payload = bytearray(struct.pack('!HH', 0, len(service)) + service)
    payload.extend(srvreqfooter)
    header = _generate_slp_header(payload, False, functionid=6, xid=xid)
    return header + payload



def _generate_request_payload(srvtype, multicast, xid, prlist=''):
    prlist = prlist.encode('utf-8')
    payload = bytearray(struct.pack('!H', len(prlist)) + prlist)
    srvtype = srvtype.encode('utf-8')
    payload.extend(struct.pack('!H', len(srvtype)) + srvtype)
    payload.extend(srvreqfooter)
    extoffset = len(payload)
    payload.extend(attrlistext)
    header = _generate_slp_header(payload, multicast, functionid=1, xid=xid,
                                  extoffset=extoffset)
    return header + payload


def _find_srvtype(net, net4, srvtype, addresses, xid):
    """Internal function to find a single service type

    Helper to do singleton requests to srvtype

    :param net: Socket active
    :param srvtype: Service type to do now
    :param addresses:  Pass through of addresses argument from find_targets
    :return:
    """
    if addresses is None:
        data = _generate_request_payload(srvtype, True, xid)
        net4.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        v6addrs = []
        v6hash = _v6mcasthash(srvtype)
        # do 'interface local' and 'link local'
        # it shouldn't make sense, but some configurations work with interface
        # local that do not work with link local
        v6addrs.append(('ff01::1:' + v6hash, 427, 0, 0))
        v6addrs.append(('ff02::1:' + v6hash, 427, 0, 0))
        for idx in util.list_interface_indexes():
            # IPv6 multicast is by index, so lead with that
            net.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)
            for sa in v6addrs:
                try:
                    net.sendto(data, sa)
                except socket.error:
                    # if we hit an interface without ipv6 multicast,
                    # this can cause an error, skip such an interface
                    # case in point, 'lo'
                    pass
        for i4 in util.list_ips():
            if 'broadcast' not in i4:
                continue
            addr = i4['addr']
            bcast = i4['broadcast']
            net4.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                           socket.inet_aton(addr))
            net4.sendto(data, ('239.255.255.253', 427))
            net4.sendto(data, (bcast, 427))


def _grab_rsps(socks, rsps, interval, xidmap):
    r, _, _ = select.select(socks, (), (), interval)
    while r:
        for s in r:
            (rsp, peer) = s.recvfrom(9000)
            neighutil.refresh_neigh()
            _parse_slp_packet(rsp, peer, rsps, xidmap)
            r, _, _ = select.select(socks, (), (), interval)



def _parse_attrlist(attrstr):
    attribs = {}
    while attrstr:
        if attrstr[0] == '(':
            if ')' not in attrstr:
                attribs['INCOMPLETE'] = True
                return attribs
            currattr = attrstr[1:attrstr.index(')')]
            if '=' not in currattr:  # Not allegedly kosher, but still..
                currattr = currattr.decode('utf-8')
                attribs[currattr] = None
            else:
                attrname, attrval = currattr.split('=')
                attrname = attrname.decode('utf-8')
                attribs[attrname] = []
                for val in attrval.split(','):
                    try:
                        val = val.decode('utf-8')
                    except UnicodeDecodeError:
                        val = '*DECODEERROR*'
                    if val[:3] == '\\FF':  # we should make this bytes
                        finalval = bytearray([])
                        for bnum in attrval[3:].split('\\'):
                            if bnum == '':
                                continue
                            finalval.append(int(bnum, 16))
                        val = finalval
                        if 'uuid' in attrname and len(val) == 16:
                            lebytes = struct.unpack_from(
                                '<IHH', buffer(val[:8]))
                            bebytes = struct.unpack_from(
                                '>HHI', buffer(val[8:]))
                            val = '{0:08X}-{1:04X}-{2:04X}-{3:04X}-' \
                                  '{4:04X}{5:08X}'.format(
                                lebytes[0], lebytes[1], lebytes[2], bebytes[0],
                                bebytes[1], bebytes[2]
                            )
                    attribs[attrname].append(val)
            attrstr = attrstr[attrstr.index(')'):]
        elif attrstr[0] == ',':
            attrstr = attrstr[1:]
        elif ',' in attrstr:
            currattr = attrstr[:attrstr.index(',')]
            attribs[currattr] = None
            attrstr = attrstr[attrstr.index(','):]
        else:
            currattr = attrstr
            attribs[currattr] = None
            attrstr = None
    print(repr(attribs))
    return attribs


def _parse_attrs(data, parsed):
    headinfo = _parse_slp_header(data)
    if headinfo['function'] != 7 or headinfo['xid'] != parsed['xid']:
        return
    payload = headinfo['payload']
    if struct.unpack('!H', bytes(payload[:2]))[0] != 0:
        return
    length = struct.unpack('!H', bytes(payload[2:4]))[0]
    attrstr = bytes(payload[4:4+length])
    parsed['attributes'] = _parse_attrlist(attrstr)


def _add_attributes(parsed):
    attrq = _generate_attr_request(parsed['services'][0], parsed['xid'])
    target = None
    # prefer reaching out to an fe80 if present, to be highly robust
    # in face of network changes
    for addr in parsed['addresses']:
        if addr[0].startswith('fe80'):
            target = addr
    # however if no fe80 seen, roll with the first available address
    if not target:
        target = parsed['addresses'][0]
    if len(target) == 4:
        net = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
        net = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    net.connect(target)
    net.sendall(attrq)
    rsp = net.recv(8192)
    net.close()
    _parse_attrs(rsp, parsed)


def query_srvtypes(target):
    """Query the srvtypes advertised by the target

    :param target: A sockaddr tuple (if you get the peer info)
    """
    payload = b'\x00\x00\xff\xff\x00\x07DEFAULT'
    header = _generate_slp_header(payload, False, functionid=9, xid=1)
    packet = header + payload
    if len(target) == 2:
        net = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    elif len(target) == 4:
        net = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
        raise Exception('Unrecognized target {0}'.format(repr(target)))
    tries = 3
    connected = False
    while tries and not connected:
        tries -= 1
        try:
            net.connect(target)
            connected = True
        except socket.error:
            pass
    if not connected:
        return [u'']
    net.sendall(packet)
    rs = net.recv(8192)
    net.close()
    parsed = _parse_slp_header(rs)
    if parsed:
        payload = parsed['payload']
        if payload[:2] != '\x00\x00':
            return
        stypelen = struct.unpack('!H', bytes(payload[2:4]))[0]
        stypes = payload[4:4+stypelen].decode('utf-8')
        return stypes.split(',')


def snoop(handler):
    """Watch for SLP activity

    handler will be called with a dictionary of relevant attributes

    :param handler:
    :return:
    """
    known_peers = set([])
    peerbymacaddress = {}
    for scanned in scan(_slp_services):
        for addr in scanned['addresses']:
            ip = addr[0].partition('%')[0]  # discard scope if present
            if ip not in neighutil.neightable:
                continue
            if addr in known_peers:
                break
            known_peers.add(addr)
        else:
            handler(scanned)
    print(repr(scanned))
    net = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    net.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    slpg = socket.inet_pton(socket.AF_INET6, 'ff01::123')
    slpg2 = socket.inet_pton(socket.AF_INET6, 'ff02::123')
    for i6idx in util.list_interface_indexes():
        mreq = slpg + struct.pack('=I', i6idx)
        net.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        mreq = slpg2 + struct.pack('=I', i6idx)
        net.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
    net4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    net.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    net4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    for i4 in util.list_ips():
        if 'broadcast' not in i4:
            continue
        slpmcast = socket.inet_aton('239.255.255.253') + \
            socket.inet_aton(i4['addr'])
        try:
            net4.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                            slpmcast)
        except socket.error as e:
            if e.errno != 98:
                raise
            # socket in use can occur when aliased ipv4 are encountered
    net.bind(('', 427))
    net4.bind(('', 427))

    while True:
        newmacs = set([])
        r, _, _ = select.select((net, net4), (), (), 60)
        neighutil.update_neigh()
        while r:
            for s in r:
                (rsp, peer) = s.recvfrom(9000)
                ip = peer[0].partition('%')[0]
                if ip not in neighutil.neightable:
                    continue
                if peer in known_peers:
                    continue
                known_peers.add(peer)
                mac = neighutil.neightable[ip]
                if mac in peerbymacaddress:
                    peerbymacaddress[mac]['peers'].append(peer)
                else:
                    q = query_srvtypes(peer)
                    if not q or not q[0]:
                        # SLP might have started and not ready yet
                        # ignore for now
                        known_peers.discard(peer)
                        continue
                    peerbymacaddress[mac] = {
                        'services': q,
                        'peers': [peer],
                    }
                newmacs.add(mac)
            r, _, _ = select.select((net, net4), (), (), 0.1)
        for mac in newmacs:
            peerinfo = {
                'hwaddr': mac,
                'addresses': peerbymacaddress[mac]['peers'],
                'services': peerbymacaddress[mac]['services'],
            }
            handler(peerinfo)


def scan(srvtypes, addresses=None):
    """Find targets providing matching requested srvtypes

    This is a generator that will iterate over respondants to the SrvType
    requested.

    :param srvtypes: An iterable list of the service types to find
    :param addresses: An iterable of addresses/ranges.  Default is to scan
                      local network segment using multicast and broadcast.
                      Each address can be a single address, hyphen-delimited
                      range, or an IP/CIDR indication of a network.
    :return: Iterable set of results
    """
    net = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    net4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # TODO: increase RCVBUF to max, mitigate chance of
    # failure due to full buffer.
    # SLP is very poor at scanning large counts and managing it, so we
    # must make the best of it
    # Some platforms/config default to IPV6ONLY, we are doing IPv4
    # too, so force it
    net.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    # we are going to do broadcast, so allow that...
    initxid = random.randint(0, 32768)
    xididx = 0
    xidmap = {}
    # First we give fast repsonders of each srvtype individual chances to be
    # processed, mitigating volume of response traffic
    rsps = {}
    for srvtype in srvtypes:
        xididx += 1
        _find_srvtype(net, net4, srvtype, addresses, initxid + xididx)
        xidmap[initxid + xididx] = srvtype
        _grab_rsps((net, net4), rsps, 0.1, xidmap)
        # now do a more slow check to work to get stragglers,
        # but fortunately the above should have taken the brunt of volume, so
        # reduced chance of many responses overwhelming receive buffer.
    _grab_rsps((net, net4), rsps, 1, xidmap)
    # now to analyze and flesh out the responses
    for id in rsps:
        _add_attributes(rsps[id])
        del rsps[id]['payload']
        del rsps[id]['function']
        del rsps[id]['xid']
        yield rsps[id]


if __name__ == '__main__':
    def testsnoop(a):
        print(repr(a))
    snoop(testsnoop)