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
# Ultimately, this should use AF_NETLINK, but in the interest of time,
# use ip neigh for the moment

import confluent.util as util
import os
import eventlet.semaphore as semaphore
import eventlet.green.socket as socket
import struct

neightable = {}
neightime = 0

import re

neighlock = semaphore.Semaphore()

def _update_neigh():
    global neightable
    global neightime
    neightime = os.times()[4]
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    s.bind((0, 0))
    # RTM_GETNEIGH
    nlhdr = b'\x1c\x00\x00\x00\x1e\x00\x01\x03\x00\x00\x00\x00\x00\x00\x00\x00'
    ndmsg=  b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    s.sendall(nlhdr + ndmsg)
    neightable = {}
    while True:
        pdata = s.recv(65536)
        v = memoryview(pdata)
        if struct.unpack('H', v[4:6])[0] == 3:
            break
        while len(v):
            length, typ = struct.unpack('IH', v[:6])
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
                        rta = rta[rtalen:]
                        if not rtalen:
                            break
                    if curraddr and currip:
                        neightable[currip] = curraddr
            v = v[length:]


def get_hwaddr(ipaddr):
    hwaddr = None
    if os.name == 'nt':
        return hwaddr
    if ':' in ipaddr:
        ipaddr = socket.inet_pton(socket.AF_INET6, ipaddr)
    elif '.' in ipaddr:
        ipaddr = socket.inet_pton(socket.AF_INET, ipaddr)
    with neighlock:
        updated = False
        if os.times()[4] > (neightime + 30):
            _update_neigh()
            updated = True
        hwaddr = neightable.get(ipaddr, None)
        if not hwaddr and not updated:
            _update_neigh()
            hwaddr = neightable.get(ipaddr, None)
    if hwaddr:
        hwaddr = ':'.join(['{:02x}'.format(x) for x in bytearray(hwaddr)])
    return hwaddr
