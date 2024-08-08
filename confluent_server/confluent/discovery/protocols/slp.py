# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2017-2019 Lenovo
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
import confluent.neighutil as neighutil
import confluent.util as util
import confluent.log as log
import os
import random
import socket
import struct
import traceback

_slp_services = set([
    'service:management-hardware.IBM:integrated-management-module2',
    'service:lenovo-smm',
    'service:lenovo-smm2',
    'service:ipmi',
    'service:lighttpd',
    #'service:management-hardware.Lenovo:lenovo-xclarity-controller',
    'service:management-hardware.IBM:chassis-management-module',
    'service:management-hardware.Lenovo:chassis-management-module',
    'service:io-device.Lenovo:management-module',
])

# SLP has a lot of ambition that was unfulfilled in practice.
# So we have a static footer here to always use 'DEFAULT' scope, no LDAP
# predicates, and no authentication for service requests
srvreqfooter = b'\x00\x07DEFAULT\x00\x00\x00\x00'
# An empty instance of the attribute list extension
# which is defined in RFC 3059, used to indicate support for that capability
attrlistext = b'\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00'

try:
    IPPROTO_IPV6 = socket.IPPROTO_IPV6
except AttributeError:
    IPPROTO_IPV6 = 41  # Assume Windows value if socket is missing it


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
    errcode = struct.unpack('!H', packet[14 + langlen:16 + langlen])[0]
    if errcode != 0:
        return None
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
    if len(payload) < 4:
        return
    ecode, ucount = struct.unpack('!HH', bytes(payload[0:4]))
    if ecode:
        parsed['errorcode'] = ecode
    payload = payload[4:]
    parsed['urls'] = []
    while ucount:
        ucount -= 1
        url, payload = _pop_url(payload)
        parsed['urls'].append(url)


def _parse_slp_packet(packet, peer, rsps, xidmap, defer=None, sock=None):
    parsed = _parse_slp_header(packet)
    if not parsed:
        return
    addr = peer[0]
    mac = neighutil.get_hwaddr(addr)
    if mac:
        identifier = mac
    else:
        if defer is None:
            identifier = addr
        else:
            probepeer = (peer[0], struct.unpack('H', os.urandom(2))[0] | 1025) + peer[2:]
            try:
                sock.setblocking(1)
                sock.sendto(b'\x00', probepeer)
            except Exception:
                return
            defer.append((packet, peer))
            return
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


async def _find_srvtype(net, net4, srvtype, addresses, xid):
    """Internal function to find a single service type

    Helper to do singleton requests to srvtype

    :param net: Socket active
    :param srvtype: Service type to do now
    :param addresses:  Pass through of addresses argument from find_targets
    :return:
    """
    cloop = asyncio.get_running_loop()
    data = _generate_request_payload(srvtype, True, xid)
    if addresses is not None:
        for addr in addresses:
            for saddr in await cloop.getaddrinfo(addr, 427):
                if saddr[0] == socket.AF_INET:
                    net4.sendto(data, saddr[4])
                elif saddr[0] == socket.AF_INET6:
                    net.sendto(data, saddr[4])
    else:
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
            net.setsockopt(IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)
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
            try:
                net4.sendto(data, ('239.255.255.253', 427))
            except socket.error as se:
                pass
            try:
                net4.sendto(data, (bcast, 427))
            except socket.error as se:
                pass


import time

def sock_read(fut, sock, cloop, allsocks):
    if fut.done():
        print("was already done???")
        return
    if not cloop.remove_reader(sock):
        print("Was already removed??")
    fut.set_result(sock)
    allsocks.discard(sock)


def _parse_attrlist(attrstr):
    attribs = {}
    previousattrlen = None
    attrstr = util.stringify(attrstr)
    while attrstr:
        if len(attrstr) == previousattrlen:
            raise Exception('Looping in attrstr parsing')
        previousattrlen = len(attrstr)
        if attrstr[0] == '(':
            if ')' not in attrstr:
                attribs['INCOMPLETE'] = True
                return attribs
            currattr = attrstr[1:attrstr.index(')')]
            if '=' not in currattr:  # Not allegedly kosher, but still..
                attribs[currattr] = None
            else:
                attrname, attrval = currattr.split('=', 1)
                attribs[attrname] = []
                for val in attrval.split(','):
                    if val[:3] == '\\FF':  # we should make this bytes
                        finalval = bytearray([])
                        for bnum in attrval[3:].split('\\'):
                            if bnum == '':
                                continue
                            finalval.append(int(bnum, 16))
                        val = finalval
                        if 'uuid' in attrname and len(val) == 16:
                            lebytes = struct.unpack_from(
                                '<IHH', memoryview(val[:8]))
                            bebytes = struct.unpack_from(
                                '>HHI', memoryview(val[8:]))
                            val = '{0:08X}-{1:04X}-{2:04X}-{3:04X}-' \
                                  '{4:04X}{5:08X}'.format(
                                lebytes[0], lebytes[1], lebytes[2], bebytes[0],
                                bebytes[1], bebytes[2]
                            ).lower()
                    attribs[attrname].append(val)
            attrstr = attrstr[attrstr.index(')'):]
        elif attrstr[0] == ','[0]:
            attrstr = attrstr[1:]
        elif ',' in attrstr:
            currattr = attrstr[:attrstr.index(',')]
            attribs[currattr] = None
            attrstr = attrstr[attrstr.index(','):]
        else:
            currattr = attrstr
            attribs[currattr] = None
            attrstr = None
    return attribs


def _parse_attrs(data, parsed, xid=None):
    headinfo = _parse_slp_header(data)
    if xid is None:
        xid = parsed['xid']
    if headinfo['function'] != 7 or headinfo['xid'] != xid:
        return
    payload = headinfo['payload']
    if struct.unpack('!H', bytes(payload[:2]))[0] != 0:
        return
    length = struct.unpack('!H', bytes(payload[2:4]))[0]
    attrstr = bytes(payload[4:4+length])
    parsed['attributes'] = _parse_attrlist(attrstr)


async def fix_info(info, handler):
    if '_attempts' not in info:
        info['_attempts'] = 10
    if info['_attempts'] == 0:
        return
    info['_attempts'] -= 1
    await _add_attributes(info)
    handler(info)


async def _add_attributes(parsed):
    xid = parsed.get('xid', 42)
    attrq = _generate_attr_request(parsed['services'][0], xid)
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
    cloop = asyncio.get_running_loop()
    try:
        net.settimeout(0)
        net.setblocking(0)
        await asyncio.wait_for(cloop.sock_connect(net, target), 2.0)
    except (socket.error, asyncio.exceptions.TimeoutError) as te:
        return
    try:
        await cloop.sock_sendall(net, attrq)
        rsp = await cloop.sock_recv(net, 8192)
        net.close()
        _parse_attrs(rsp, parsed, xid)
    except Exception as e:
        # this can be a messy area, just degrade the quality of rsp
        # in a bad situation
        return


def unicast_scan(address):
    pass

async def query_srvtypes(target):
    """Query the srvtypes advertised by the target

    :param target: A sockaddr tuple (if you get the peer info)
    """
    cloop = asyncio.get_running_loop()
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
            net.settimeout(0)
            await asyncio.wait_for(cloop.sock_connect(net, target), 2.0)
            connected = True
        except (socket.error, asyncio.exceptions.TimeoutError) as te:
            return [u'']
    await cloop.sock_sendall(net, packet)
    rs = await cloop.sock_recv(net, 8192)
    net.close()
    parsed = _parse_slp_header(rs)
    if parsed:
        payload = parsed['payload']
        if payload[:2] != b'\x00\x00':
            return
        stypelen = struct.unpack('!H', bytes(payload[2:4]))[0]
        stypes = payload[4:4+stypelen].decode('utf-8')
        return stypes.split(',')

async def rescan(handler):
    known_peers = set([])
    async for scanned in scan():
        for addr in scanned['addresses']:
            if addr in known_peers:
                break
            macaddr = neighutil.get_hwaddr(addr[0])
            if not macaddr:
                continue
            known_peers.add(addr)
        else:
            handler(scanned)


def relay_packet(sock, pktq):
    sock.setblocking(0)
    try:
        rsp, peer = sock.recvfrom(9000)
    except socket.error as se:
        return
    pktq.put_nowait((sock, rsp, peer))

async def snoop(handler, protocol=None):
    """Watch for SLP activity

    handler will be called with a dictionary of relevant attributes

    :param handler:
    :return:
    """
    tracelog = log.Logger('trace')
    try:
        await active_scan(handler, protocol)
    except Exception as e:
        tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                        event=log.Events.stacktrace)
    net = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    net.setsockopt(IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    slpg = socket.inet_pton(socket.AF_INET6, 'ff01::123')
    slpg2 = socket.inet_pton(socket.AF_INET6, 'ff02::123')
    for i6idx in util.list_interface_indexes():
        mreq = slpg + struct.pack('=I', i6idx)
        net.setsockopt(IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        mreq = slpg2 + struct.pack('=I', i6idx)
        net.setsockopt(IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
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
    pktq = asyncio.Queue()
    cloop = asyncio.get_running_loop()
    cloop.add_reader(net, relay_packet, net, pktq)
    cloop.add_reader(net4, relay_packet, net4, pktq)
    newmacs = set([])
    known_peers = set([])
    peerbymacaddress = {}
    deferpeers = []
    while True:
        try:
            newmacs.clear()
            r, _, _ = select.select((net, net4), (), (), 60)
            # clear known_peers and peerbymacaddress
            # to avoid stale info getting in...
            # rely upon the select(0.2) to catch rapid fire and aggregate ip
            # addresses that come close together
            # calling code needs to understand deeper context, as snoop
            # will now yield dupe info over time
            known_peers.clear()
            peerbymacaddress.clear()
            deferpeers.clear()
            timeo = 60
            rdy = True
            srp = await pktq.get()
            while srp and len(deferpeers) < 256:
                s, rsp, peer = srp
                if peer in known_peers:
                    continue
                mac = neighutil.get_hwaddr(peer[0])
                if not mac:
                    probepeer = (peer[0], struct.unpack('H', os.urandom(2))[0] | 1025) + peer[2:]
                    try:
                        s.setblocking(1)
                        s.sendto(b'\x00', probepeer)
                    except Exception as e:
                        try:
                            srp = await asyncio.wait_for(pktq.get(), 0.2)
                        except asyncio.exceptions.TimeoutError:
                            break
                        continue
                    deferpeers.append(peer)
                    continue
                await process_peer(newmacs, known_peers, peerbymacaddress, peer)
                if len(deferpeers) >= 256:
                    break
                try:
                    srp = await asyncio.wait_for(pktq.get(), 0.2)
                except asyncio.exceptions.TimeoutError:
                    break
            if deferpeers:
                await asyncio.sleep(2.2)
                for peer in deferpeers:
                    await process_peer(newmacs, known_peers, peerbymacaddress, peer)
            for mac in newmacs:
                peerbymacaddress[mac]['xid'] = 1
                await _add_attributes(peerbymacaddress[mac])
                peerbymacaddress[mac]['hwaddr'] = mac
                peerbymacaddress[mac]['protocol'] = protocol
                for srvurl in peerbymacaddress[mac].get('urls', ()):
                    if len(srvurl) > 4:
                        srvurl = srvurl[:-3]
                    if srvurl.endswith('://Athena:'):
                        continue
                if 'service:ipmi' in peerbymacaddress[mac]['services']:
                    continue
                if 'service:lightttpd' in peerbymacaddress[mac]['services']:
                    currinf = peerbymacaddress[mac]
                    curratt = currinf.get('attributes', {})
                    if curratt.get('System-Manufacturing', [None])[0] == 'Lenovo' and curratt.get('type', [None])[0] == 'LenovoThinkServer':
                        peerbymacaddress[mac]['services'] = ['service:lenovo-tsm']
                    else:
                        continue
                handler(peerbymacaddress[mac])
        except Exception as e:
            tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                         event=log.Events.stacktrace)

async def process_peer(newmacs, known_peers, peerbymacaddress, peer):
    mac = neighutil.get_hwaddr(peer[0])
    if not mac:
        return
    known_peers.add(peer)
    if mac in peerbymacaddress:
        peerbymacaddress[mac]['addresses'].append(peer)
    else:
        try:
            q = await query_srvtypes(peer)
        except Exception as e:
            q = None
        if not q or not q[0]:
            # SLP might have started and not ready yet
            # ignore for now
            known_peers.discard(peer)
            return
        # we want to prioritize the very well known services
        svcs = []
        for svc in q:
            if svc in _slp_services:
                svcs.insert(0, svc)
            else:
                svcs.append(svc)
        peerbymacaddress[mac] = {
                            'services': svcs,
                            'addresses': [peer],
                        }
    newmacs.add(mac)


async def active_scan(handler, protocol=None):
    known_peers = set([])
    # Implement a warmup, inducing neighbor table activity
    # by kernel and giving 2 seconds for a retry or two if
    # needed
    async for scanned in scan():
        for addr in scanned['addresses']:
            if addr in known_peers:
                break
            macaddr = neighutil.get_hwaddr(addr[0])
            if not macaddr:
                continue
            if not scanned.get('hwaddr', None):
                scanned['hwaddr'] = macaddr
            known_peers.add(addr)
        else:
            scanned['protocol'] = protocol
            handler(scanned)


async def scan(srvtypes=_slp_services, addresses=None, localonly=False):
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
    # increase RCVBUF to max, mitigate chance of
    # failure due to full buffer.
    net.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16777216)
    net4.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16777216)
    # SLP is very poor at scanning large counts and managing it, so we
    # must make the best of it
    # Some platforms/config default to IPV6ONLY, we are doing IPv4
    # too, so force it
    #net.setsockopt(IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    # we are going to do broadcast, so allow that...
    cloop = asyncio.get_running_loop()
    pktq = asyncio.Queue()
    cloop.add_reader(net, relay_packet, net, pktq)
    cloop.add_reader(net4, relay_packet, net4, pktq)
    initxid = random.randint(0, 32768)
    xididx = 0
    xidmap = {}
    # First we give fast repsonders of each srvtype individual chances to be
    # processed, mitigating volume of response traffic
    rsps = {}
    deferrals = []
    rcvq = asyncio.Queue()
    for srvtype in srvtypes:
        xididx += 1
        await _find_srvtype(net, net4, srvtype, addresses, initxid + xididx)
        xidmap[initxid + xididx] = srvtype
        await asyncio.sleep(0)  # give async a chance to move things off buffer to queue
    while True:
        try:
            srp = await asyncio.wait_for(pktq.get(), 1.0)
            sock, rsp, peer = srp
            _parse_slp_packet(rsp, peer, rsps, xidmap, deferrals, sock)
        except asyncio.exceptions.TimeoutError:
            break
    cloop.remove_reader(net)
    cloop.remove_reader(net4)
    if deferrals:
        await asyncio.sleep(1.2)  # already have a one second pause from select above
        for defer in deferrals:
            rsp, peer = defer
            _parse_slp_packet(rsp, peer, rsps, xidmap)
    # now to analyze and flesh out the responses
    handleids = set([])
    tsks = []
    for id in rsps:
        for srvurl in rsps[id].get('urls', ()):
            if len(srvurl) > 4:
                srvurl = srvurl[:-3]
            if srvurl.endswith('://Athena:'):
                continue
        if 'service:ipmi' in rsps[id]['services']:
            continue
        if localonly:
            for addr in rsps[id]['addresses']:
                if 'fe80' in addr[0]:
                    break
            else:
                continue
        tsks.append(util.spawn(_add_attributes(rsps[id])))
        handleids.add(id)
    if tsks:
        await asyncio.wait(tsks)
    for id in handleids:
        if 'service:lighttpd' in rsps[id]['services']:
            currinf = rsps[id]
            curratt = currinf.get('attributes', {})
            if curratt.get('System-Manufacturing', [None])[0] == 'Lenovo' and curratt.get('type', [None])[0] == 'LenovoThinkServer':
               currinf['services'] = ['service:lenovo-tsm']
               serialnumber = curratt.get('Product-Serial', curratt.get('SerialNumber', None))
               if serialnumber:
                   curratt['enclosure-serial-number'] = serialnumber
               mtm = curratt.get('Machine-Type', curratt.get('Product-Name', None))
               if mtm:
                   mtm[0] = mtm[0].rstrip()
                   curratt['enclosure-machinetype-model'] = mtm
            else:
                continue
        del rsps[id]['payload']
        del rsps[id]['function']
        del rsps[id]['xid']
        yield rsps[id]


if __name__ == '__main__':
    def testsnoop(a):
        print(repr(a))
    snoop(testsnoop)
