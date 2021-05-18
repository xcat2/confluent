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

# We can listen to port 69 with SO_REUSEADDR to snoop port 69 *even* if dhcp
# is running (because the other dhcp servers do it already)

# Goal is to detect and act on a DHCPDISCOVER, without actually having to do
# any offer

# option 97 = UUID (wireformat)

import confluent.config.configmanager as cfm
import confluent.collective.manager as collective
import confluent.noderange as noderange
import confluent.log as log
import confluent.netutil as netutil
import ctypes
import ctypes.util
import eventlet
import eventlet.green.socket as socket
import eventlet.green.select as select
import netifaces
import struct
import traceback

libc = ctypes.CDLL(ctypes.util.find_library('c'))

iphdr = b'\x45\x00\x00\x00\x00\x00\x00\x00\x40\x11\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff'
constiphdrsum = b'\x85\x11'
udphdr = b'\x00\x43\x00\x44\x00\x00\x00\x00'

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

class iovec(ctypes.Structure):   # from uio.h
    _fields_ = [('iov_base', ctypes.c_void_p),
                ('iov_len', ctypes.c_size_t)]

class msghdr(ctypes.Structure):  # from bits/socket.h
    _fields_ = [('msg_name', ctypes.c_void_p),
                ('msg_namelen', ctypes.c_uint),
                ('msg_iov', ctypes.POINTER(iovec)),
                ('msg_iovlen', ctypes.c_size_t),
                ('msg_control', ctypes.c_void_p),
                ('msg_controllen', ctypes.c_size_t),
                ('msg_flags', ctypes.c_int)]

class cmsghdr(ctypes.Structure):  # also from bits/socket.h
    _fields_ = [('cmsg_len', ctypes.c_size_t),
                ('cmsg_level', ctypes.c_int),
                ('cmsg_type', ctypes.c_int)]
                # ignore the __extension__

class in_addr(ctypes.Structure):
    _fields_ = [('s_addr', ctypes.c_uint32)]

class in_pktinfo(ctypes.Structure):  # from bits/in.h
    _fields_ = [('ipi_ifindex', ctypes.c_int),
                ('ipi_spec_dst', in_addr),
                ('ipi_addr', in_addr)]

class sockaddr_in(ctypes.Structure):
    _fields_ = [('sin_family', ctypes.c_ushort),  # per bits/sockaddr.h
                ('sin_port', ctypes.c_uint16),  # per netinet/in.h
                ('sin_addr', in_addr)]


sendto = libc.sendto
sendto.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t,
                   ctypes.c_int, ctypes.POINTER(sockaddr_ll),
                   ctypes.c_size_t]
sendto.restype = ctypes.c_size_t
recvmsg = libc.recvmsg
recvmsg.argtypes = [ctypes.c_int, ctypes.POINTER(msghdr), ctypes.c_int]
recvmsg.restype = ctypes.c_size_t

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


def CMSG_ALIGN(length):  # bits/socket.h
    ret = (length + ctypes.sizeof(ctypes.c_size_t) - 1
           & ~(ctypes.sizeof(ctypes.c_size_t) - 1))
    return ctypes.c_size_t(ret)


def CMSG_SPACE(length):  # bits/socket.h
    ret = CMSG_ALIGN(length).value + CMSG_ALIGN(ctypes.sizeof(cmsghdr)).value
    return ctypes.c_size_t(ret)


cmsgtype = ctypes.c_char * CMSG_SPACE(ctypes.sizeof(in_pktinfo)).value
cmsgsize = CMSG_SPACE(ctypes.sizeof(in_pktinfo)).value

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
    vci = stringify(reqdict.get(60, b''))
    if vci.startswith('cumulus-linux'):
        disco['arch'] = vci.replace('cumulus-linux', '').strip()
        iscumulus = True
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

def proxydhcp():
    net4011 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    net4011.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    net4011.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
    net4011.bind(('', 4011))
    cfg = cfm.ConfigManager(None)
    while True:
        ready = select.select([net4011], [], [], None)
        if not ready or not ready[0]:
            continue
        rq = bytearray(1024)
        rqv = memoryview(rq)
        nb, client = net4011.recvfrom_into(rq)
        if nb < 240:
            continue
        rp = bytearray(1024)
        rpv = memoryview(rp)
        try:
            optidx = rq.index(b'\x63\x82\x53\x63') + 4
        except ValueError:
            continue
        hwlen = rq[2]
        opts, disco = opts_to_dict(rq, optidx, 3)
        disco['hwaddr'] = ':'.join(['{0:02x}'.format(x) for x in rq[28:28+hwlen]])
        node = None
        if disco.get('hwaddr', None) in macmap:
            node = macmap[disco['hwaddr']]
        elif disco.get('uuid', None) in uuidmap:
            node = uuidmap[disco['uuid']]
        if not node:
            continue

        myipn = myipbypeer.get(rqv[28:28+hwlen].tobytes(), None)
        if not myipn:
            continue
        if opts.get(77, None) == b'iPXE':
            profile = get_deployment_profile(node, cfg)
            if not profile:
                continue
            myip = socket.inet_ntoa(myipn)
            bootfile = 'http://{0}/confluent-public/os/{1}/boot.ipxe'.format(myip, profile).encode('utf8')
        elif disco['arch'] == 'uefi-x64':
            bootfile = b'confluent/x86_64/ipxe.efi'
        elif disco['arch'] == 'bios-x86':
            bootfile = b'confluent/x86_64/ipxe.kkpxe'
        if len(bootfile) > 127:
            log.log(
                {'info': 'Boot offer cannot be made to {0} as the '
                'profile name "{1}" is {2} characters longer than is supported '
                'for this boot method.'.format(
                    node, profile, len(bootfile) - 127)})
            continue
        rpv[:240] = rqv[:240].tobytes()
        rpv[0:1] = b'\x02'
        rpv[108:108 + len(bootfile)] = bootfile
        rpv[240:243] = b'\x35\x01\x05'
        rpv[243:249] = b'\x36\x04' + myipn
        rpv[20:24] = myipn
        rpv[249:268] = b'\x61\x11' + opts[97]
        rpv[268:280] = b'\x3c\x09PXEClient\xff'
        net4011.sendto(rpv[:281], client)


def start_proxydhcp():
    eventlet.spawn_n(proxydhcp)


def snoop(handler, protocol=None):
    #TODO(jjohnson2): ipv6 socket and multicast for DHCPv6, should that be
    #prominent
    #TODO(jjohnson2): enable unicast replies. This would suggest either
    # injection into the neigh table before OFFER or using SOCK_RAW.
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
    net4.bind(('', 67))
    while True:
        try:
            # Just need some delay, picked a prime number so that overlap with other
            # timers might be reduced, though it really is probably nothing
            ready = select.select([net4], [], [], None)
            if not ready or not ready[0]:
                continue
            clientaddr = sockaddr_in()
            rawbuffer = bytearray(2048)
            data = pkttype.from_buffer(rawbuffer)
            msg = msghdr()
            cmsgarr = bytearray(cmsgsize)
            cmsg = cmsgtype.from_buffer(cmsgarr)
            iov = iovec()
            iov.iov_base = ctypes.addressof(data)
            iov.iov_len = 2048
            msg.msg_iov = ctypes.pointer(iov)
            msg.msg_iovlen = 1
            msg.msg_control = ctypes.addressof(cmsg)
            msg.msg_controllen = ctypes.sizeof(cmsg)
            msg.msg_name = ctypes.addressof(clientaddr)
            msg.msg_namelen = ctypes.sizeof(clientaddr)
            # We'll leave name and namelen blank for now
            i = recvmsg(net4.fileno(), ctypes.pointer(msg), 0)
            # if we have a small packet, just skip, it can't possible hold enough
            # data and avoids some downstream IndexErrors that would be messy
            # with try/except
            if i < 64:
                continue
            #peer = ipfromint(clientaddr.sin_addr.s_addr)
            # We don't need peer yet, generally it's 0.0.0.0
            _, level, typ = struct.unpack('QII', cmsgarr[:16])
            if level == socket.IPPROTO_IP and typ == IP_PKTINFO:
                idx, recv, targ = struct.unpack('III', cmsgarr[16:28])
                recv = ipfromint(recv)
                targ = ipfromint(targ)
            # peer is the source ip (in dhcpdiscover, 0.0.0.0)
            # recv is the 'ip' that recevied the packet, regardless of target
            # targ is the ip in the destination ip of the header.
            # idx is the ip link number of the receiving nic
            # For example, a DHCPDISCOVER will probably have:
            # peer of 0.0.0.0
            # targ of 255.255.255.255
            # recv of <actual ip address that could reply>
            # idx correlated to the nic
            rqv = memoryview(rawbuffer)
            rq = bytearray(rqv[:i])
            if rq[0] == 1:  # Boot request
                addrlen = rq[2]
                if addrlen > 16 or addrlen == 0:
                    continue
                rawnetaddr = rq[28:28+addrlen]
                netaddr = ':'.join(['{0:02x}'.format(x) for x in rawnetaddr])
                optidx = 0
                try:
                    optidx = rq.index(b'\x63\x82\x53\x63') + 4
                except ValueError:
                    continue
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
                    handler(info)
                    #consider_discover(info, rqinfo, net4, cfg, rqv)
                    continue
                # We will fill out service to have something to byte into,
                # but the nature of the beast is that we do not have peers,
                # so that will not be present for a pxe snoop
                info = {'hwaddr': netaddr, 'uuid': disco['uuid'],
                        'architecture': disco['arch'],
                        'netinfo': {'ifidx': idx, 'recvip': recv, 'txid': txid},
                        'services': ('pxe-client',)}
                if disco['uuid']:  #TODO(jjohnson2): need to explictly check for
                                # discover, so that the parser can go ahead and
                                # parse the options including uuid to enable
                                # ACK
                    handler(info)
                consider_discover(info, rqinfo, net4, cfg, rqv)
        except Exception as e:
            tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                            event=log.Events.stacktrace)



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
        cfd = cfg.get_node_attributes(node, ('deployment.*'))
    profile = cfd.get(node, {}).get('deployment.pendingprofile', {}).get('value', None)
    if not profile:
        return None
    candmgrs = cfd.get(node, {}).get('collective.managercandidates', {}).get('value', None)
    if candmgrs:
        candmgrs = noderange.NodeRange(candmgrs, cfg).nodes
        if collective.get_myname() not in candmgrs:
            return None
    return profile

staticassigns = {}
myipbypeer = {}
def check_reply(node, info, packet, sock, cfg, reqview):
    httpboot = info['architecture'] == 'uefi-httpboot'
    replen = 275  # default is going to be 286
    cfd = cfg.get_node_attributes(node, ('deployment.*'))
    profile = get_deployment_profile(node, cfg, cfd)
    if not profile:
        return
    myipn = info['netinfo']['recvip']
    myipn = socket.inet_aton(myipn)

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
    repview[12:16] = myipn
    repview[20:28] = udphdr
    repview = repview[28:]
    repview[0:1] = b'\x02'
    repview[1:10] = reqview[1:10] # duplicate txid, hwlen, and others
    repview[10:11] = b'\x80'  # always set broadcast
    repview[28:44] = reqview[28:44]  # copy chaddr field
    if httpboot:
        proto = 'https' if insecuremode == 'never' else 'http'
        bootfile = '{0}://{1}/confluent-public/os/{2}/boot.img'.format(
            proto, info['netinfo']['recvip'], profile
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
    repview[20:24] = myipn
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
    if niccfg['ipv4_address'] and niccfg['ipv4_method'] != 'firmwaredhcp':
        clipn = socket.inet_aton(niccfg['ipv4_address'])
        repview[16:20] = clipn
        gateway = niccfg['ipv4_gateway']
        if gateway:
            gateway = socket.inet_aton(gateway)
        netmask = niccfg['prefix']
        netmask = (2**32 - 1) ^ (2**(32 - netmask) - 1)
        netmask = struct.pack('!I', netmask)
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
        ipinfo = 'without address'
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

def consider_discover(info, packet, sock, cfg, reqview):
    if info.get('hwaddr', None) in macmap and info.get('uuid', None):
        check_reply(macmap[info['hwaddr']], info, packet, sock, cfg, reqview)
    elif info.get('uuid', None) in uuidmap:
        check_reply(uuidmap[info['uuid']], info, packet, sock, cfg, reqview)
    elif packet.get(53, None) == b'\x03':
        ack_request(packet, reqview, info)


if __name__ == '__main__':
    def testsnoop(info):
        print(repr(info))
    snoop(testsnoop)
