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

# A consolidated manage of neighbor table information management.

import asyncio
import os
import socket
import struct


def msg_align(len):
    return (len + 3) & ~3


neightable = {}
ipbymac = {}
neightime = 0


neighlock = None

async def _update_neigh():
    global neightable
    global ipbymac
    global neightime
    neightime = os.times()[4]
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    s.bind((0, 0))
    s.settimeout(0)
    # RTM_GETNEIGH
    # nlmsghdr struct: u32 len, u16 type, u16 flags, u32 seq, u32 pid
    nlhdr = b'\x1c\x00\x00\x00\x1e\x00\x01\x03\x00\x00\x00\x00\x00\x00\x00\x00'
    # ndmsg struct u8 family u8 pad, u16 pad, s32 ifidx, u16 state, u8 flags, u8 type
    ndmsg=  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    cloop = asyncio.get_running_loop()
    await cloop.sock_sendall(s, nlhdr + ndmsg)
    #s.sendall(nlhdr + ndmsg)
    neightable = {}
    ipbymac = {}
    inprogress = True
    try:
        while inprogress:
            pdata = await cloop.sock_recv(s, 65536)
            v = memoryview(pdata)
            while len(v):
                length, typ = struct.unpack('IH', v[:6])
                if typ == 3:
                    inprogress = False
                if typ == 28:
                    hlen = struct.calcsize('BIHBB')
                    _, idx, state, flags, typ = struct.unpack('BIHBB', v[16:16+hlen])
                    if typ == 1:  # only handle unicast entries
                        curraddr = None
                        currip = None
                        rta = v[16+hlen:length]
                        while len(rta):
                            rtalen, rtatyp = struct.unpack('HH', rta[:4])
                            if rtatyp == 2:  # hwaddr
                                curraddr = rta[4:rtalen].tobytes()
                                if len(curraddr) == 20:
                                    curraddr = curraddr[12:]
                            elif rtatyp == 1:  # ip address
                                currip = rta[4:rtalen].tobytes()
                            rta = rta[msg_align(rtalen):]
                            if not rtalen:
                                break
                        if curraddr and currip:
                            neightable[currip] = curraddr
                            ipbymac.setdefault(curraddr, []).append({'ip': currip, 'ifidx': idx})
                v = v[msg_align(length):]
    finally:
        s.close()


async def ipn_is_local(ipn):
    if len(ipn) > 5 and ipn.startswith(b'\xfe\x80'):
        return True
    for addr in await get_my_addresses():
        if len(addr[1]) != len(ipn):
            continue
        if ipn_on_same_subnet(addr[0], ipn, addr[1], addr[2]):
            return True
    return False

def ipn_on_same_subnet(fam, first, second, prefix):
    if fam == socket.AF_INET6:
        if prefix > 64:
            firstmask = 0xffffffffffffffff
            secondmask = (2**64-1) ^ (2**(128 - prefix) - 1)
        else:
            firstmask = (2**64-1) ^ (2**(64 - prefix) - 1)
            secondmask = 0
        first = struct.unpack('!QQ', first)
        second = struct.unpack('!QQ', second)
        return ((first[0] & firstmask == second[0] & firstmask)
            and (first[1] & secondmask == second[1] & secondmask))
    else:
        mask = (2**32 - 1) ^ (2**(32 - prefix) - 1)
        first = struct.unpack('!I', first)[0]
        second = struct.unpack('!I', second)[0]
        return (first & mask == second & mask)

nlhdrsz = struct.calcsize('IHHII')
ifaddrsz = struct.calcsize('BBBBI')

async def get_my_addresses(idx=0, family=0, matchlla=None):
    # RTM_GETADDR = 22
    # nlmsghdr struct: u32 len, u16 type, u16 flags, u32 seq, u32 pid
    nlhdr = struct.pack('IHHII', nlhdrsz + ifaddrsz, 22, 0x301, 0, 0)
    # ifaddrmsg struct: u8 family, u8 prefixlen, u8 flags, u8 scope, u32 index
    ifaddrmsg = struct.pack('BBBBI', family, 0, 0, 0, idx)
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    try:
        s.bind((0, 0))
        s.setblocking(False)
        await asyncio.get_running_loop().sock_sendall(s, nlhdr + ifaddrmsg)
        addrs = []
        while True:
            pdata = await asyncio.get_running_loop().sock_recv(s, 65536)
            v = memoryview(pdata)
            if struct.unpack('H', v[4:6])[0] == 3:  # netlink done message
                break
            while len(v):
                length, typ = struct.unpack('IH', v[:6])
                if typ == 20:
                    fam, plen, _, scope, ridx = struct.unpack('BBBBI', v[nlhdrsz:nlhdrsz+ifaddrsz])
                    if matchlla:
                        if scope == 253:
                            rta = v[nlhdrsz+ifaddrsz:length]
                            while len(rta):
                                rtalen, rtatyp = struct.unpack('HH', rta[:4])
                                if rtalen < 4:
                                    break
                                if rta[4:rtalen].tobytes() == matchlla:
                                    return await get_my_addresses(idx=ridx)
                                rta = rta[msg_align(rtalen):]
                    elif (ridx == idx or not idx) and scope == 0:
                        rta = v[nlhdrsz+ifaddrsz:length]
                        while len(rta):
                            rtalen, rtatyp = struct.unpack('HH', rta[:4])
                            if rtalen < 4:
                                break
                            if rtatyp == 1:
                                addrs.append((fam, rta[4:rtalen].tobytes(), plen, ridx))
                            rta = rta[msg_align(rtalen):]
                v = v[msg_align(length):]
    finally:
        s.close()
    return addrs

async def get_ipaddr(hwaddr):
    global neighlock
    ipaddr = None
    if neighlock is None:
        neighlock = asyncio.Lock()
    hwaddrbytes = bytes.fromhex(hwaddr.replace(':', ''))
    async with neighlock:
        updated = False
        if os.times()[4] > (neightime + 30):
            await _update_neigh()
            updated = True
        ipaddr = ipbymac.get(hwaddrbytes, [])
        if not ipaddr and not updated:
            await _update_neigh()
            ipaddr = ipbymac.get(hwaddrbytes, [])
    return ipaddr

async def get_hwaddr(ipaddr):
    if '%' in ipaddr:
        ipaddr, _ = ipaddr.split('%', 1)
    hwaddr = None
    if os.name == 'nt':
        return hwaddr
    if ':' in ipaddr:
        ipaddr = socket.inet_pton(socket.AF_INET6, ipaddr)
    elif '.' in ipaddr:
        ipaddr = socket.inet_pton(socket.AF_INET, ipaddr)
    global neighlock
    if neighlock is None:
        neighlock = asyncio.Lock()
    async with neighlock:
        updated = False
        if os.times()[4] > (neightime + 30):
            await _update_neigh()
            updated = True
        hwaddr = neightable.get(ipaddr, None)
        if not hwaddr and not await ipn_is_local(ipaddr):
            hwaddr = False
        if hwaddr is None and not updated:
            await _update_neigh()
            hwaddr = neightable.get(ipaddr, None)
    if hwaddr:
        hwaddr = ':'.join(['{:02x}'.format(x) for x in bytearray(hwaddr)])
    return hwaddr


if __name__ == '__main__':
    import sys
    print(repr(get_hwaddr(sys.argv[1])))
