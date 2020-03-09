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

import ctypes
import ctypes.util
import eventlet.green.socket as socket
import eventlet.green.select as select
import struct

libc = ctypes.CDLL(ctypes.util.find_library('c'))

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


recvmsg = libc.recvmsg
recvmsg.argtypes = [ctypes.c_int, ctypes.POINTER(msghdr), ctypes.c_int]
recvmsg.restype = ctypes.c_size_t

pkttype = ctypes.c_char * 2048


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
    '\x00\x00': 'bios-x86',
    '\x00\x07': 'uefi-x64',
    '\x00\x09': 'uefi-x64',
    '\x00\x0b': 'uefi-aarch64',
    '\x00\x10': 'uefi-httpboot',
}


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


def find_info_in_options(rq, optidx):
    uuid = None
    arch = None
    vivso = None
    ztpurlrequested = False
    iscumulus = False
    try:
        while uuid is None or arch is None:
            if rq[optidx] == 53:  # DHCP message type
                # we want only length 1 and only discover (type 1)
                if rq[optidx + 1] != 1 or rq[optidx + 2] != 1:
                    return uuid, arch, vivso
                optidx += 3
            elif rq[optidx] == 55:
                if 239 in rq[optidx + 2:optidx + 2 + rq[optidx + 1]]:
                    ztpurlrequested = True
                optidx += rq[optidx + 1] + 2
            elif rq[optidx] == 60:
                vci = stringify(rq[optidx + 2:optidx + 2 + rq[optidx + 1]])
                if vci.startswith('cumulus-linux'):
                    iscumulus = True
                    arch = vci.replace('cumulus-linux', '').strip()
                optidx += rq[optidx + 1] + 2
            elif rq[optidx] == 97:
                if rq[optidx + 1] != 17:
                    # 16 bytes of uuid and one reserved byte
                    return uuid, arch, vivso
                if rq[optidx + 2] != 0:  # the reserved byte should be zero,
                    # anything else would be a new spec that we don't know yet
                    return uuid, arch, vivso
                uuid = decode_uuid(rq[optidx + 3:optidx + 19])
                optidx += 19
            elif rq[optidx] == 93:
                if rq[optidx + 1] != 2:
                    return uuid, arch
                archraw = bytes(rq[optidx + 2:optidx + 4])
                if archraw in pxearchs:
                    arch = pxearchs[archraw]
                optidx += 4
            elif rq[optidx] == 125:
                #vivso = rq[optidx + 2:optidx + 2 + rq[optidx + 1]]
                if rq[optidx + 2:optidx + 6] == b'\x00\x00\xa6\x7f':  # OCP
                    return _decode_ocp_vivso(rq, optidx + 7, rq[optidx + 6])
                optidx += rq[optidx + 1] + 2
            else:
                optidx += rq[optidx + 1] + 2
    except IndexError:
        pass
    if not vivso and iscumulus and ztpurlrequested:
        if not uuid:
            uuid = ''
        vivso = {'service-type': 'cumulus-switch', 'arch': arch}
    return uuid, arch, vivso

def ipfromint(numb):
    return socket.inet_ntoa(struct.pack('I', numb))

def snoop(handler, protocol=None):
    #TODO(jjohnson2): ipv6 socket and multicast for DHCPv6, should that be
    #prominent
    #TODO(jjohnson2): enable unicast replies. This would suggest either
    # injection into the neigh table before OFFER or using SOCK_RAW.
    net4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    net4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    net4.setsockopt(socket.IPPROTO_IP, IP_PKTINFO, 1)
    net4.bind(('', 67))
    while True:
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
        rq = memoryview(rawbuffer)
        rq = bytearray(rq[:i])
        if rq[0] == 1:  # Boot request
            addrlen = rq[2]
            if addrlen > 16 or addrlen == 0:
                continue
            netaddr = rq[28:28+addrlen]
            netaddr = ':'.join(['{0:02x}'.format(x) for x in netaddr])
            optidx = 0
            try:
                optidx = rq.index(b'\x63\x82\x53\x63') + 4
            except ValueError:
                continue
            uuid, arch, vivso = find_info_in_options(rq, optidx)
            if vivso:
                # info['modelnumber'] = info['attributes']['enclosure-machinetype-model'][0]
                handler({'hwaddr': netaddr, 'uuid': uuid,
                         'architecture': vivso.get('arch', ''),
                         'services': (vivso['service-type'],),
                         'netinfo': {'ifidx': idx, 'recvip': recv},
                         'attributes': {'enclosure-machinetype-model': [vivso.get('machine', '')]}})
                continue
            if uuid is None:
                continue
            # We will fill out service to have something to byte into,
            # but the nature of the beast is that we do not have peers,
            # so that will not be present for a pxe snoop
            handler({'hwaddr': netaddr, 'uuid': uuid, 'architecture': arch,
                     'netinfo': {'ifidx': idx, 'recvip': recv},
                     'services': ('pxe-client',)})

if __name__ == '__main__':
    def testsnoop(info):
        print(repr(info))
    snoop(testsnoop)


