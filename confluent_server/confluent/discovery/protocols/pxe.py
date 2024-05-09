# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2017-2021 Lenovo
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

# We can listen to port 69 with SO_REUSEADDR to snoop port 69 *even* if dhcp
# is running (because the other dhcp servers do it already)

# Goal is to detect and act on a DHCPDISCOVER, without actually having to do
# any offer

# option 97 = UUID (wireformat)

import asyncio
import confluent.config.configmanager as cfm
import confluent.collective.manager as collective
import confluent.noderange as noderange
import confluent.neighutil as neighutil
import confluent.log as log
import confluent.netutil as netutil
import confluent.util as util
import ctypes
import ctypes.util
import eventlet
import eventlet.green.socket as socket
import eventlet.green.select as select
import netifaces
import struct
import time
import traceback
import uuid

libc = ctypes.CDLL(ctypes.util.find_library('c'))

iphdr = b'\x45\x00\x00\x00\x00\x00\x00\x00\x40\x11\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff'
constiphdrsum = b'\x85\x11'
udphdr = b'\x00\x43\x00\x44\x00\x00\x00\x00'
ignoremacs = {}
ignoredisco = {}

mcastv6addr = 'ff02::1:2'


def _ipsum(data):
    currsum = 0
    if len(data) % 2:
        currsum = struct.unpack('!B', data[-1:])[0] << 8
        data = memoryview(data)
        data = data[:-1]
    for datum in struct.unpack('!' + 'H' * (len(data) // 2), data):
        currsum += datum
        if currsum >> 16:
            currsum &= 0xffff
            currsum += 1
    if currsum == 0:
        currsum = 0xffff
    return currsum

class sockaddr_ll(ctypes.Structure):
    _fields_ = [('sll_family', ctypes.c_ushort),
                ('sll_protocol', ctypes.c_ushort),
                ('sll_ifindex', ctypes.c_int),
                ('sll_hatype', ctypes.c_ushort),
                ('sll_pkttype', ctypes.c_ubyte),
                ('sll_halen', ctypes.c_ubyte),
                ('sll_addr', ctypes.c_ubyte * 20)]


sendto = libc.sendto
sendto.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t,
                   ctypes.c_int, ctypes.POINTER(sockaddr_ll),
                   ctypes.c_size_t]
sendto.restype = ctypes.c_size_t


pkttype = ctypes.c_char * 2048

_idxtoname = libc.if_indextoname
_idxtoname.argtypes = [ctypes.c_uint, ctypes.c_char_p]

def idxtoname(idx):
    name = (ctypes.c_char * 16)()
    _idxtoname(idx, name)
    ret = name.value.strip()
    if not isinstance(ret, str):
        ret = ret.decode('utf8')
    return ret

_idxtobcast = {}
def get_bcastaddr(idx):
    if idx not in _idxtobcast:
        bc = netifaces.ifaddresses(idxtoname(idx))[17][0]['broadcast']
        bc = bytearray([int(x, 16) for x in bc.split(':')])
        _idxtobcast[idx] = bc
    return _idxtobcast[idx]


IP_PKTINFO = 8


pxearchs = {
    b'\x00\x00': 'bios-x86',
    b'\x00\x07': 'uefi-x64',
    b'\x00\x09': 'uefi-x64',
    b'\x00\x0b': 'uefi-aarch64',
    b'\x00\x10': 'uefi-httpboot',
}


uuidmap = {}
macmap = {}
attribwatcher = None

def stringify(value):
    string = bytes(value)
    if not isinstance(string, str):
        string = string.decode('utf8')
    return string

def decode_uuid(rawguid):
    lebytes = struct.unpack_from('<IHH', rawguid[:8])
    bebytes = struct.unpack_from('>HHI', rawguid[8:])
    return '{0:08X}-{1:04X}-{2:04X}-{3:04X}-{4:04X}{5:08X}'.format(
        lebytes[0], lebytes[1], lebytes[2], bebytes[0], bebytes[1], bebytes[2]).lower()


def _decode_ocp_vivso(rq, idx, size):
    end = idx + size
    vivso = {'service-type': 'onie-switch'}
    while idx < end:
        if rq[idx] == 3:
            vivso['machine'] = stringify(rq[idx + 2:idx + 2 + rq[idx + 1]])
        elif rq[idx] == 4:
            vivso['arch'] = stringify(rq[idx + 2:idx + 2 + rq[idx + 1]])
        elif rq[idx] == 5:
            vivso['revision'] = stringify(rq[idx + 2:idx + 2 + rq[idx + 1]])
        idx += rq[idx + 1] + 2
    return '', None, vivso

def v6opts_to_dict(rq):
    optidx = 0
    reqdict = {}
    disco = {'uuid':None, 'arch': None, 'vivso': None}
    try:
        while optidx < len(rq):
            optnum, optlen = struct.unpack('!HH', rq[optidx:optidx+4])
            reqdict[optnum] = rq[optidx + 4:optidx + 4 + optlen]
            optidx += optlen + 4
    except IndexError:
        pass
    reqdict['vci'] = None
    if 16 in reqdict:
        vco = reqdict[16]
        iananum, vlen = struct.unpack('!IH', vco[:6])
        vci = vco[6:vlen + 6]
        if vci.startswith(b'HTTPClient:Arch') or vci.startswith(b'PXEClient:Arch:'):
            reqdict['vci'] = vci.decode('utf8')
    if 1 in reqdict:
        duid = reqdict[1]
        if struct.unpack('!H', duid[:2])[0] == 4:
            disco['uuid'] = decode_uuid(duid[2:])
    if 61 in reqdict:
        arch = bytes(rq[optidx+4:optidx+4+optlen])
        disco['arch'] = pxearchs.get(bytes(reqdict[61]), None)
    return reqdict, disco

def opts_to_dict(rq, optidx, expectype=1):
    reqdict = {}
    disco = {'uuid':None, 'arch': None, 'vivso': None}
    try:
        while optidx < len(rq):
            optnum = rq[optidx]
            optlen = rq[optidx + 1]
            reqdict[optnum] = rq[optidx + 2:optidx + 2 + optlen]
            optidx += optlen + 2
    except IndexError:
        pass
    if reqdict.get(53, [0])[0] != expectype:
        return reqdict, disco
    # It is a discover packet..
    iscumulus = False
    maybeztp = False
    if 239 in reqdict.get(55, []):
        maybeztp = True
    try:
        vci = stringify(reqdict.get(60, b''))
    except UnicodeDecodeError:
        vci = ''
    reqdict['vci'] = None
    if vci.startswith('cumulus-linux'):
        disco['arch'] = vci.replace('cumulus-linux', '').strip()
        iscumulus = True
    elif vci.startswith('HTTPClient:Arch') or vci.startswith('PXEClient'):
        reqdict['vci'] = vci
    if reqdict.get(93, None):
        disco['arch'] = pxearchs.get(bytes(reqdict[93]), None)
    if reqdict.get(97, None):
        uuidcandidate = reqdict[97]
        if uuidcandidate[0] != 0:
            return reqdict, disco
        disco['uuid'] = decode_uuid(uuidcandidate[1:])
    if reqdict.get(125, None):
        if reqdict[125][:4] == b'\x00\x00\xa6\x7f':  # OCP
            disco['vivso'] = _decode_ocp_vivso(
                reqdict[125], 5, reqdict[125][4])[-1]
            return reqdict, disco
    if not disco['vivso'] and iscumulus and maybeztp:
        if not disco['uuid']:
            disco['uuid'] = ''
        disco['vivso'] = {'service-type': 'cumulus-switch',
                          'arch': disco['arch']}
    return reqdict, disco


def ipfromint(numb):
    return socket.inet_ntoa(struct.pack('I', numb))

def relay_proxydhcp(sock, pktq):
    sock.setblocking(0)
    data, cmsgs, flags, peer = sock.recvmsg(9000, 9000)
    if len(data) < 240:
        return
    try:
        optidx = data.index(b'\x63\x82\x53\x63') + 4
    except ValueError:
        return
    for cmsg in cmsgs:
        level, typ, cdata = cmsg
        if level == socket.IPPROTO_IP and typ == IP_PKTINFO:
            idx, recv = struct.unpack('II', cdata[:8])
            recv = ipfromint(recv)
            break
    else:
        return
    rq = memoryview(data)
    hwlen = rq[2]
    opts, disco = opts_to_dict(rq, optidx, 3)
    disco['hwaddr'] = ':'.join(['{0:02x}'.format(x) for x in rq[28:28+hwlen]])
    node = None
    if disco.get('hwaddr', None) in macmap:
        node = macmap[disco['hwaddr']]
    elif disco.get('uuid', None) in uuidmap:
        node = uuidmap[disco['uuid']]
    myipn = myipbypeer.get(data[28:28+hwlen], None)
    skiplogging = True
    pktq.put_nowait((disco, peer, myipn, idx, recv, node, opts, data))


async def proxydhcp(handler, nodeguess):
    net4011 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    net4011.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    net4011.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
    net4011.bind(('', 4011))
    cloop = asyncio.get_running_loop()
    pktq = asyncio.Queue()
    cloop.add_reader(net4011, relay_proxydhcp, net4011, pktq)
    cfg = cfm.ConfigManager(None)
    while True:
        try:
            disco, client, myipn, idx, recv, node, opts, data = await pktq.get()
            netaddr = disco['hwaddr']
            if time.time() > ignoredisco.get(netaddr, 0) + 90:
                skiplogging = False
                ignoredisco[netaddr] = time.time()
            if not myipn:
                info = {'hwaddr': netaddr, 'uuid': disco['uuid'],
                                'architecture': disco['arch'],
                                'netinfo': {'ifidx': idx, 'recvip': recv},
                                'services': ('pxe-client',)}
                if not skiplogging:
                    handler(info)
            if not node:
                if not myipn and not skiplogging:
                    log.log(
                            {'info': 'No node matches boot attempt from uuid {0} or hardware address {1}'.format(
                                disco.get('uuid', 'unknown'), disco.get('hwaddr', 'unknown')
                    )})
                continue
            profile = None
            if not myipn:
                myipn = socket.inet_aton(recv)
                profile = get_deployment_profile(node, cfg)
                if profile:
                    log.log({
                        'info': 'Offering proxyDHCP boot from {0} to {1} ({2})'.format(recv, node, client[0])})
                else:
                    if not skiplogging:
                        log.log({'info': 'No pending profile for {0}, skipping proxyDHCP reply'.format(node)})
                    continue
            if opts.get(77, None) == b'iPXE':
                if not profile:
                    profile = get_deployment_profile(node, cfg)
                if not profile:
                    log.log({'info': 'No pending profile for {0}, skipping proxyDHCP reply'.format(node)})
                    continue
                myip = socket.inet_ntoa(myipn)
                bootfile = 'http://{0}/confluent-public/os/{1}/boot.ipxe'.format(myip, profile).encode('utf8')
            elif disco['arch'] == 'uefi-x64':
                bootfile = b'confluent/x86_64/ipxe.efi'
            elif disco['arch'] == 'bios-x86':
                bootfile = b'confluent/x86_64/ipxe.kkpxe'
            elif disco['arch'] == 'uefi-aarch64':
                bootfile = b'confluent/aarch64/ipxe.efi'
            if len(bootfile) > 127:
                log.log(
                    {'info': 'Boot offer cannot be made to {0} as the '
                    'profile name "{1}" is {2} characters longer than is supported '
                    'for this boot method.'.format(
                        node, profile, len(bootfile) - 127)})
                continue
            rp = bytearray(300)
            rpv = memoryview(rp)
            rqv = memoryview(data)
            rpv[:240] = rqv[:240].tobytes()
            rpv[0:1] = b'\x02'
            rpv[108:108 + len(bootfile)] = bootfile
            rpv[240:243] = b'\x35\x01\x05'
            rpv[243:249] = b'\x36\x04' + myipn
            rpv[20:24] = myipn
            rpv[249:268] = b'\x61\x11' + opts[97]
            rpv[268:280] = b'\x3c\x09PXEClient\xff'
            net4011.sendto(rpv[:281], client)
        except Exception as e:
            tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                            event=log.Events.stacktrace)


def start_proxydhcp(handler, nodeguess=None):
    util.spawn(proxydhcp(handler, nodeguess))


def new_dhcp_packet(handler, nodeguess, cfg, net4):
    data, cmsgs, flags, peer = net4.recvmsg(9000, 9000)
    if len(data) < 64:
        return
    for cmsg in cmsgs:
        level, typ, cdata = cmsg
        if level == socket.IPPROTO_IP and typ == IP_PKTINFO:
            idx, recv = struct.unpack('II', cdata[:8])
            recv = ipfromint(recv)
        rqv = memoryview(data)
        if rqv[0] == 1:
            process_dhcp4req(handler, nodeguess, cfg, net4, idx, recv, rqv)


def new_dhcp6_packet(handler, net6, cfg, nodeguess):
    recv = 'ff02::1:2'
    pkt, addr = net6.recvfrom(2048)
    idx = addr[-1]
    if len(pkt) < 64:
        return
    rqv = memoryview(pkt)
    if rqv[0] in (1, 3):
        process_dhcp6req(handler, rqv, addr, net6, cfg, nodeguess)


async def snoop(handler, protocol=None, nodeguess=None):
    #TODO(jjohnson2): ipv6 socket and multicast for DHCPv6, should that be
    #prominent
    #TODO(jjohnson2): enable unicast replies. This would suggest either
    # injection into the neigh table before OFFER or using SOCK_RAW.
    start_proxydhcp(handler, nodeguess)
    global tracelog
    tracelog = log.Logger('trace')
    global attribwatcher
    cfg = cfm.ConfigManager(None)
    remap_nodes(cfg.list_nodes(), cfg)
    attribwatcher = cfg.watch_attributes(cfg.list_nodes(), ('id.uuid', 'net.*hwaddr'), remap_nodes)
    cfg.watch_nodecollection(new_nodes)
    net4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    net4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    net4.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    net4.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
    try:
        net4.bind(('', 67))
    except Exception:
        log.log({'error': 'Unable to bind DHCP server port, if using dnsmasq, specify bind-dynamic in dnsmasq.conf and restart dnsmasq and then confluent'})
        return
    v6addr = socket.inet_pton(socket.AF_INET6, mcastv6addr)
    net6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    net6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    for ifidx in util.list_interface_indexes():
        v6grp = v6addr + struct.pack('=I', ifidx)
        net6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, v6grp)
    net6.bind(('', 547))
    net6.settimeout(0)
    net4.settimeout(0)
    cloop = asyncio.get_running_loop()
    cloop.add_reader(net4, new_dhcp_packet, handler, nodeguess, cfg, net4)
    cloop.add_reader(net6, new_dhcp6_packet, handler, net6, cfg, nodeguess)


def process_dhcp6req(handler, rqv, addr, net, cfg, nodeguess):
    ip = addr[0]
    req, disco = v6opts_to_dict(bytearray(rqv[4:]))
    req['txid'] = rqv[1:4]
    req['rqtype'] = bytearray(rqv[:1])[0]
    if not disco.get('uuid', None) or not disco.get('arch', None):
        return
    if disco['uuid'] == '03000200-0400-0500-0006-000700080009':
        # Ignore common malformed dhcpv6 request from firmware
        return
    mac = neighutil.get_hwaddr(ip.split('%', 1)[0])
    if not mac:
        net.sendto(b'\x00', addr)
    tries = 5
    while tries and not mac:
        eventlet.sleep(0.01)
        tries -= 1
        mac = neighutil.get_hwaddr(ip.split('%', 1)[0])
    info = {'hwaddr': mac, 'uuid': disco['uuid'],
            'architecture': disco['arch'], 'services': ('pxe-client',)}
    if ignoredisco.get(mac, 0) + 90 < time.time():
        ignoredisco[mac] = time.time()
        handler(info)
    consider_discover(info, req, net, cfg, None, nodeguess, addr)

def process_dhcp4req(handler, nodeguess, cfg, net4, idx, recv, rqv):
    rq = bytearray(rqv)
    addrlen = rq[2]
    if addrlen > 16 or addrlen == 0:
        return
    rawnetaddr = rq[28:28+addrlen]
    netaddr = ':'.join(['{0:02x}'.format(x) for x in rawnetaddr])
    optidx = 0
    try:
        optidx = rq.index(b'\x63\x82\x53\x63') + 4
    except ValueError:
        return
    txid = rq[4:8] # struct.unpack('!I', rq[4:8])[0]
    rqinfo, disco = opts_to_dict(rq, optidx)
    vivso = disco.get('vivso', None)
    if vivso:
                        # info['modelnumber'] = info['attributes']['enclosure-machinetype-model'][0]
        info = {'hwaddr': netaddr, 'uuid': disco['uuid'],
                                'architecture': vivso.get('arch', ''),
                                'services': (vivso['service-type'],),
                                'netinfo': {'ifidx': idx, 'recvip': recv, 'txid': txid},
                                'attributes': {'enclosure-machinetype-model': [vivso.get('machine', '')]}}
        if time.time() > ignoredisco.get(netaddr, 0) + 90:
            ignoredisco[netaddr] = time.time()
            handler(info)
                        #consider_discover(info, rqinfo, net4, cfg, rqv)
        return
                    # We will fill out service to have something to byte into,
                    # but the nature of the beast is that we do not have peers,
                    # so that will not be present for a pxe snoop
    info = {'hwaddr': netaddr, 'uuid': disco['uuid'],
                            'architecture': disco['arch'],
                            'netinfo': {'ifidx': idx, 'recvip': recv, 'txid': txid},
                            'services': ('pxe-client',)}
    if (disco['uuid']
                            and time.time() > ignoredisco.get(netaddr, 0) + 90):
        ignoredisco[netaddr] = time.time()
        handler(info)
    consider_discover(info, rqinfo, net4, cfg, rqv, nodeguess)



def clear_nodes(nodes):
    for nodename in nodes:
        for ent in list(macmap):
            if macmap[ent] == nodename:
                del macmap[ent]
        for ent in list(uuidmap):
            if uuidmap[ent] == nodename:
                del uuidmap[ent]


def new_nodes(added, deleting, renamed, configmanager):
    global attribwatcher
    configmanager.remove_watcher(attribwatcher)
    alldeleting = set(deleting) | set(renamed)
    clear_nodes(alldeleting)
    alladding = set(added)
    for oldname in renamed:
        alladding.add(renamed[oldname])
    remap_nodes(alladding, configmanager)
    attribwatcher = configmanager.watch_attributes(configmanager.list_nodes(),
                                                   ('id.uuid', 'net.*hwaddr'), remap_nodes)


def remap_nodes(nodeattribs, configmanager):
    global macmap
    global uuidmap
    updates = configmanager.get_node_attributes(nodeattribs, ('id.uuid', 'net.*hwaddr'))
    clear_nodes(nodeattribs)
    for node in updates:
        for attrib in updates[node]:
            if attrib == 'id.uuid':
                uuidmap[updates[node][attrib]['value'].lower()] = node
            elif 'hwaddr' in attrib:
                macmap[updates[node][attrib]['value'].lower()] = node


def get_deployment_profile(node, cfg, cfd=None):
    if not cfd:
        cfd = cfg.get_node_attributes(node, ('deployment.*', 'collective.managercandidates'))
    profile = cfd.get(node, {}).get('deployment.pendingprofile', {}).get('value', None)
    if not profile:
        return None
    candmgrs = cfd.get(node, {}).get('collective.managercandidates', {}).get('value', None)
    if candmgrs:
        try:
            candmgrs = noderange.NodeRange(candmgrs, cfg).nodes
        except Exception: # fallback to unverified noderange
            candmgrs = noderange.NodeRange(candmgrs).nodes
        if collective.get_myname() not in candmgrs:
            return None
    return profile

staticassigns = {}
myipbypeer = {}
def check_reply(node, info, packet, sock, cfg, reqview, addr):
    httpboot = info['architecture'] == 'uefi-httpboot'
    cfd = cfg.get_node_attributes(node, ('deployment.*', 'collective.managercandidates'))
    profile = get_deployment_profile(node, cfg, cfd)
    if not profile:
        if time.time() > ignoremacs.get(info['hwaddr'], 0) + 90:
            ignoremacs[info['hwaddr']] = time.time()
            log.log({'info': 'Ignoring boot attempt by {0} no deployment profile specified (uuid {1}, hwaddr {2})'.format(
                node, info['uuid'], info['hwaddr']
            )})
        return
    if addr:
        if packet['vci'] and packet['vci'].startswith('PXEClient'):
            log.log({'info': 'IPv6 PXE boot attempt by {0}, but IPv6 PXE is not supported, try IPv6 HTTP boot or IPv4 boot'.format(node)})
            return
        return reply_dhcp6(node, addr, cfg, packet, cfd, profile, sock)
    else:
        return reply_dhcp4(node, info, packet, cfg, reqview, httpboot, cfd, profile)

def reply_dhcp6(node, addr, cfg, packet, cfd, profile, sock):
    myaddrs = netutil.get_my_addresses(addr[-1], socket.AF_INET6)
    if not myaddrs:
        log.log({'info': 'Unable to provide IPv6 boot services to {0}, no viable IPv6 configuration on interface index "{1}" to respond through.'.format(node, addr[-1])})
        return
    niccfg = netutil.get_nic_config(cfg, node, ifidx=addr[-1])
    ipv6addr = niccfg.get('ipv6_address', None)
    ipv6prefix = niccfg.get('ipv6_prefix', None)
    ipv6method = niccfg.get('ipv6_method', 'static')
    ipv6srvaddr = niccfg.get('deploy_server_v6', None)
    if not ipv6srvaddr:
        log.log({'info': 'Unable to determine an appropriate ipv6 server ip for {}'.format(node)})
        return
    insecuremode = cfd.get(node, {}).get('deployment.useinsecureprotocols',
        {}).get('value', 'never')
    if not insecuremode:
        insecuremode = 'never'
    proto = 'https' if insecuremode == 'never' else 'http'
    bootfile = '{0}://[{1}]/confluent-public/os/{2}/boot.img'.format(
        proto, ipv6srvaddr, profile
    )
    if not isinstance(bootfile, bytes):
        bootfile = bootfile.encode('utf8')
    ipass = []
    if ipv6method == 'firmwarenone':
        return
    if ipv6method not in ('dhcp', 'firmwaredhcp') and ipv6addr:
        if not ipv6prefix:
            log.log({'info': 'Unable to determine prefix to serve to address {} for node {}'.format(ipv6addr, node)})
            return
        ipass = bytearray(40)
        ipass[:4] = packet[3][:4]  # pass iaid back
        ipass[4:16] = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x18'
        ipass[16:32] = socket.inet_pton(socket.AF_INET6, ipv6addr)
        ipass[32:40] = b'\x00\x00\x00\x78\x00\x00\x01\x2c'
    elif (not packet['vci']) or not packet['vci'].startswith('HTTPClient:Arch:'):
        return # do not send ip-less replies to anything but HTTPClient specifically
    #1 msgtype
    #3 txid
    #22 - server ident
    #len(packet[1]) + 4 - client ident
    #len(ipass) + 4 or 0
    #len(url) + 4
    replylen = 50 + len(bootfile) + len(packet[1]) + 4
    if len(ipass):
        replylen += len(ipass)
    reply = bytearray(replylen)
    reply[0] = 2 if packet['rqtype'] == 1 else 7
    reply[1:4] = packet['txid']
    offset = 4
    struct.pack_into('!HH', reply, offset, 1, len(packet[1]))
    offset += 4
    reply[offset:offset+len(packet[1])] = packet[1]
    offset += len(packet[1])
    struct.pack_into('!HHH', reply, offset, 2, 18, 4)
    offset += 6
    reply[offset:offset+16] = get_my_duid()
    offset += 16
    if ipass:
        struct.pack_into('!HH', reply, offset, 3, len(ipass))
        offset += 4
        reply[offset:offset + len(ipass)] = ipass
        offset += len(ipass)
    struct.pack_into('!HH', reply, offset, 59, len(bootfile))
    offset += 4
    reply[offset:offset + len(bootfile)] = bootfile
    offset += len(bootfile)
    # Need the HTTPClient in the vendor class for reply
    struct.pack_into('!HHIH', reply, offset, 16, 16, 0, 10)
    offset += 10
    reply[offset:offset + 10] = b'HTTPClient'
    sock.sendto(reply, addr)


_myuuid = None
def get_my_duid():
    global _myuuid
    if not _myuuid:
        _myuuid = uuid.uuid4().bytes
    return _myuuid


def reply_dhcp4(node, info, packet, cfg, reqview, httpboot, cfd, profile):
    replen = 275  # default is going to be 286
    # while myipn is describing presumed destination, it's really
    # vague in the face of aliases, need to convert to ifidx and evaluate
    # aliases for best match to guess

    rqtype = packet[53][0]
    insecuremode = cfd.get(node, {}).get('deployment.useinsecureprotocols',
        {}).get('value', 'never')
    if not insecuremode:
        insecuremode = 'never'
    if insecuremode == 'never' and not httpboot:
        if rqtype == 1 and info['architecture']:
            log.log(
                {'info': 'Boot attempt by {0} detected in insecure mode, but '
                        'insecure mode is disabled.  Set the attribute '
                        '`deployment.useinsecureprotocols` to `firmware` or '
                        '`always` to enable support, or use UEFI HTTP boot '
                        'with HTTPS.'.format(node)})
        return
    reply = bytearray(512)
    repview = memoryview(reply)
    repview[:20] = iphdr
    repview[20:28] = udphdr
    orepview = repview
    repview = repview[28:]
    repview[0:1] = b'\x02'
    repview[1:10] = reqview[1:10] # duplicate txid, hwlen, and others
    repview[10:11] = b'\x80'  # always set broadcast
    repview[28:44] = reqview[28:44]  # copy chaddr field
    gateway = None
    netmask = None
    niccfg = netutil.get_nic_config(cfg, node, ifidx=info['netinfo']['ifidx'])
    nicerr = niccfg.get('error_msg', False)
    if nicerr:
        log.log({'error': nicerr})
    if niccfg.get('ipv4_broken', False):
        # Received a request over a nic with no ipv4 configured, ignore it
        log.log({'error': 'Skipping boot reply to {0} due to no viable IPv4 configuration on deployment system'.format(node)})
        return
    clipn = None
    if niccfg['ipv4_method'] == 'firmwarenone':
        return
    if niccfg['ipv4_address'] and niccfg['ipv4_method'] != 'firmwaredhcp':
        clipn = socket.inet_aton(niccfg['ipv4_address'])
        repview[16:20] = clipn
        gateway = niccfg['ipv4_gateway']
        netmask = niccfg['prefix']
        if gateway:
            gateway = socket.inet_aton(gateway)
            if not netutil.ipn_on_same_subnet(socket.AF_INET, clipn, gateway, netmask):
                log.log(
                    {'warning': 'Ignoring gateway {0} due to mismatch with address {1}/{2}'.format(niccfg['ipv4_gateway'], niccfg['ipv4_address'], netmask)})
                gateway = None
        netmask = (2**32 - 1) ^ (2**(32 - netmask) - 1)
        netmask = struct.pack('!I', netmask)
    elif (not packet['vci']) or not (packet['vci'].startswith('HTTPClient:Arch:') or packet['vci'].startswith('PXEClient')):
        return  # do not send ip-less replies to anything but netboot specifically
    myipn = niccfg['deploy_server']
    if not myipn:
        myipn = info['netinfo']['recvip']
    if httpboot:
        proto = 'https' if insecuremode == 'never' else 'http'
        bootfile = '{0}://{1}/confluent-public/os/{2}/boot.img'.format(
            proto, myipn, profile
        )
        if not isinstance(bootfile, bytes):
            bootfile = bootfile.encode('utf8')
        if len(bootfile) > 127:
            log.log(
                {'info': 'Boot offer cannot be made to {0} as the '
                'profile name "{1}" is {2} characters longer than is supported '
                'for this boot method.'.format(
                    node, profile, len(bootfile) - 127)})
            return
        repview[108:108 + len(bootfile)] = bootfile
    elif info['architecture'] == 'uefi-aarch64' and packet.get(77, None) == b'iPXE':
        if not profile:
            profile = get_deployment_profile(node, cfg)
        if not profile:
            log.log({'info': 'No pending profile for {0}, skipping proxyDHCP eply'.format(node)})
            return
        bootfile = 'http://{0}/confluent-public/os/{1}/boot.ipxe'.format(myipn, profile).encode('utf8')
        repview[108:108 + len(bootfile)] = bootfile
    myip = myipn
    myipn = socket.inet_aton(myipn)
    orepview[12:16] = myipn
    repview[20:24] = myipn
    repview[236:240] = b'\x63\x82\x53\x63'
    repview[240:242] = b'\x35\x01'
    if rqtype == 1:  # if discover, then offer
        repview[242:243] = b'\x02'
    elif rqtype == 3: # if request, then ack
        repview[242:243] = b'\x05'
    repview[243:245] = b'\x36\x04' # DHCP server identifier
    repview[245:249] = myipn
    repview[249:255] = b'\x33\x04\x00\x00\x00\xf0'  # fixed short lease time
    repview[255:257] = b'\x61\x11'
    repview[257:274] = packet[97]
    # Note that sending PXEClient kicks off the proxyDHCP procedure, ignoring
    # boot filename and such in the DHCP packet
    # we will simply always do it to provide the boot payload in a consistent
    # matter to both dhcp-elsewhere and fixed ip clients
    if info['architecture'] == 'uefi-httpboot':
        repview[replen - 1:replen + 11] = b'\x3c\x0aHTTPClient'
        replen += 12
    else:
        repview[replen - 1:replen + 10] = b'\x3c\x09PXEClient'
        replen += 11
    hwlen = bytearray(reqview[2:3].tobytes())[0]
    fulladdr = repview[28:28+hwlen].tobytes()
    myipbypeer[fulladdr] = myipn
    if hwlen == 8: # omnipath may present a mangled proxydhcp request later
        shortaddr = bytearray(6)
        shortaddr[0] = 2
        shortaddr[1:] = fulladdr[3:]
        myipbypeer[bytes(shortaddr)] = myipn
    if netmask:
        repview[replen - 1:replen + 1] = b'\x01\x04'
        repview[replen + 1:replen + 5] = netmask
        replen += 6
    if gateway:
        repview[replen - 1:replen + 1] = b'\x03\x04'
        repview[replen + 1:replen + 5] = gateway
        replen += 6
    if 82 in packet:
        reloptionslen = len(packet[82])
        reloptionshdr = struct.pack('BB', 82, reloptionslen)
        repview[replen - 1:replen + 1] = reloptionshdr
        repview[replen + 1:replen + reloptionslen + 1] = packet[82]
        replen += 2 + reloptionslen

    repview[replen - 1:replen] = b'\xff'  # end of options, should always be last byte
    repview = memoryview(reply)
    pktlen = struct.pack('!H', replen + 28)  # ip+udp = 28
    repview[2:4] = pktlen
    curripsum = ~(_ipsum(constiphdrsum + pktlen + myipn)) & 0xffff
    repview[10:12] = struct.pack('!H', curripsum)
    repview[24:26] = struct.pack('!H', replen + 8)
    datasum = _ipsum(b'\x00\x11' + repview[24:26].tobytes() +
                     repview[12:replen + 28].tobytes())
    datasum = ~datasum & 0xffff
    repview[26:28] = struct.pack('!H', datasum)
    if clipn:
        staticassigns[fulladdr] = (clipn, repview[:replen + 28].tobytes())
    elif fulladdr in staticassigns:
        del staticassigns[fulladdr]
    if httpboot:
        boottype = 'HTTP'
    else:
        boottype = 'PXE'
    if clipn:
        ipinfo = 'with static address {0}'.format(niccfg['ipv4_address'])
    else:
        ipinfo = 'without address, served from {0}'.format(myip)
    log.log({
        'info': 'Offering {0} boot {1} to {2}'.format(boottype, ipinfo, node)})
    send_raw_packet(repview, replen + 28, reqview, info)

def send_raw_packet(repview, replen, reqview, info):
    ifidx = info['netinfo']['ifidx']
    tsock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM,
                          socket.htons(0x800))
    targ = sockaddr_ll()
    bcastaddr = get_bcastaddr(ifidx)
    hwlen = len(bcastaddr)
    bcastaddr20 = bytearray(20)
    bcastaddr20[:hwlen] = bcastaddr
    targ.sll_addr = (ctypes.c_ubyte * 20).from_buffer(bcastaddr20)
    targ.sll_family = socket.AF_PACKET
    targ.sll_halen = hwlen
    targ.sll_protocol = socket.htons(0x800)
    targ.sll_ifindex = ifidx
    try:
        pkt = ctypes.byref((ctypes.c_char * (replen)).from_buffer(repview))
    except TypeError:
        # Python 2....
        pkt = ctypes.byref((ctypes.c_char * (replen)).from_buffer_copy(
            repview[:replen].tobytes()))
    sendto(tsock.fileno(), pkt, replen, 0, ctypes.byref(targ),
           ctypes.sizeof(targ))

def ack_request(pkt, rq, info):
    hwlen = bytearray(rq[2:3].tobytes())[0]
    hwaddr = rq[28:28+hwlen].tobytes()
    myipn = myipbypeer.get(hwaddr, None)
    if not myipn or pkt.get(54, None) != myipn:
        return
    assigninfo = staticassigns.get(hwaddr, None)
    if assigninfo == None:
        return
    if pkt.get(50, None) != assigninfo[0]:
        return
    rply = assigninfo[1]
    reply = bytearray(512)
    repview = memoryview(reply)
    repview[:len(rply)] = rply
    repview[270:271] = b'\x05'
    repview[26:28] = struct.pack('!H', 0) # TODO: use datasum, it was incorrect)
    datasum = _ipsum(b'\x00\x11' + repview[24:26].tobytes() +
                     repview[12:len(rply)].tobytes())
    datasum = ~datasum & 0xffff
    repview[26:28] = struct.pack('!H', datasum)
    send_raw_packet(repview, len(rply), rq, info)

def consider_discover(info, packet, sock, cfg, reqview, nodeguess, addr=None):
    if info.get('hwaddr', None) in macmap and info.get('uuid', None):
        check_reply(macmap[info['hwaddr']], info, packet, sock, cfg, reqview, addr)
    elif info.get('uuid', None) in uuidmap:
        check_reply(uuidmap[info['uuid']], info, packet, sock, cfg, reqview, addr)
    elif packet.get(53, None) == b'\x03':
        ack_request(packet, reqview, info)
    elif info.get('uuid', None) and info.get('hwaddr', None):
        if time.time() > ignoremacs.get(info['hwaddr'], 0) + 90:
            ignoremacs[info['hwaddr']] = time.time()
            maybenode = None
            if nodeguess:
                maybenode = nodeguess(info['uuid'])
            if maybenode:
                # originally was going to just offer up the node (the likely
                # scenario is that it was manually added, autodiscovery picked
                # up the TLS match, and correlated)
                # However, since this is technically unverified data, we shouldn't
                # act upon it until confirmed by process or user
                # So instead, offer a hint about what is probably the case, but
                # hasn't yet been approved by anything
                log.log(
                        {'info': 'Boot attempt from uuid {0} or hardware '
                                 'address {1}, which is not confirmed to be a '
                                 'node, but seems to be {2}. To confirm node '
                                 'identity, \'nodediscover reassign -n {2}\' or '
                                 '\'nodeattrib {2} id.uuid={0}\''.format(
                            info['uuid'], info['hwaddr'], maybenode
                )})
            else:
                log.log(
                        {'info': 'No node matches boot attempt from uuid {0} or hardware address {1}'.format(
                            info['uuid'], info['hwaddr']
                )})


if __name__ == '__main__':
    def testsnoop(info):
        print(repr(info))
    snoop(testsnoop)
