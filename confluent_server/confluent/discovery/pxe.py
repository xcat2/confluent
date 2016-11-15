# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2016 Lenovo
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

import eventlet.green.socket as socket
import struct

pxearchs = {
    '\x00\x00': 'bios-x86',
    '\x00\x07': 'uefi-x64',
    '\x00\x09': 'uefi-x64',
    '\x00\x0b': 'uefi-aarch64',
}


def decode_uuid(rawguid):
    lebytes = struct.unpack_from('<IHH', buffer(rawguid[:8]))
    bebytes = struct.unpack_from('>HHI', buffer(rawguid[8:]))
    return '{0:08X}-{1:04X}-{2:04X}-{3:04X}-{4:04X}{5:08X}'.format(
        lebytes[0], lebytes[1], lebytes[2], bebytes[0], bebytes[1], bebytes[2])


def find_info_in_options(rq, optidx):
    uuid = None
    arch = None
    try:
        while uuid is None or arch is None:
            if rq[optidx] == 53:  # DHCP message type
                # we want only length 1 and only discover (type 2)
                if rq[optidx + 1] != 1 or rq[optidx + 2] != 1:
                    return uuid, arch
                optidx += 3
            elif rq[optidx] == 97:
                if rq[optidx + 1] != 17:
                    # 16 bytes of uuid and one reserved byte
                    return uuid, arch
                if rq[optidx + 2] != 0:  # the reserved byte should be zero,
                    # anything else would be a new spec that we don't know yet
                    return uuid, arch
                uuid = decode_uuid(rq[optidx + 3:optidx + 19])
                optidx += 19
            elif rq[optidx] == 93:
                if rq[optidx + 1] != 2:
                    return uuid, arch
                archraw = bytes(rq[optidx + 2:optidx + 4])
                if archraw in pxearchs:
                    arch = pxearchs[archraw]
            else:
                optidx += rq[optidx + 1] + 2
    except IndexError:
        return uuid, arch
    return uuid, arch

def snoop(handler):
    #TODO(jjohnson2): ipv6 socket and multicast for DHCPv6, should that be
    #prominent
    #TODO(jjohnson2): IP_PKTINFO, recvmsg to get the destination ip, per
    #proxydhcp.c from xCAT
    net4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    net4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    net4.bind(('', 67))
    while True:
        # Just need some delay, picked a prime number so that overlap with other
        # timers might be reduced, though it really is probably nothing
        (rq, peer) = net4.recvfrom(9000)
        # if we have a small packet, just skip, it can't possible hold enough
        # data and avoids some downstream IndexErrors that would be messy
        # with try/except
        if len(rq) < 64:
            continue
        rq = bytearray(rq)
        if rq[0] == 1:  # Boot request
            addrlen = rq[2]
            if addrlen > 16:  # max address size in bootp is 16 bytes
                continue
            netaddr = rq[28:28+addrlen]
            netaddr = ':'.join(['{0:02x}'.format(x) for x in netaddr])
            optidx = 0
            try:
                optidx = rq.index('\x63\x82\x53\x63') + 4
            except ValueError:
                continue
            uuid, arch = find_info_in_options(rq, optidx)
            if uuid is None:
                continue
            handler(netaddr, uuid, arch)

if __name__ == '__main__':
    def testsnoop(addr, uuid, arch):
        print(addr)
        print(uuid)
        print(arch)
    snoop(testsnoop)


