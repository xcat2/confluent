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
# this will implement noderange grammar


import socket
import struct
import eventlet.support.greendns
getaddrinfo = eventlet.support.greendns.getaddrinfo


def get_prefix_len_for_ip(ip):
    # for now, we'll use the system route table
    # later may provide for configuration lookup to override the route
    # table
    ip = getaddrinfo(ip, 0, socket.AF_INET)[0][-1][0]
    try:
        ipn = socket.inet_aton(ip)
    except socket.error:  # For now, assume 64 for ipv6
        return 64
    # It comes out big endian, but as document /proc/net/route is little endian
    # byte swap the result
    ipn = struct.unpack('<I', ipn)[0]
    rf = open('/proc/net/route')
    ri = rf.read()
    rf.close()
    ri = ri.split('\n')[1:]
    for rl in ri:
        if not rl:
            continue
        rd = rl.split('\t')
        if rd[1] == '00000000':  # default gateway, not useful for this
            continue
        maskn = int(rd[7], 16)
        netn = int(rd[1], 16)
        if ipn & maskn == netn:
            nbits = 0
            while maskn:
                nbits += 1
                maskn = maskn >> 1
            return nbits
