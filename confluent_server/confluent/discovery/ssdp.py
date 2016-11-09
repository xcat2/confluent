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

# Documented somewhat at
# http://buildingskb.schneider-electric.com/view.php?AID=15197
import confluent.util as util
import select
import socket

mcastv4addr = '239.255.255.250'
mcastv6addr = 'ff02::c'

smsg = ('M-SEARCH * HTTP/1.1\r\n'
        'HOST: {0}:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        'ST: {1}\r\n'
        'MX: 3\r\n\r\n')


def find_targets(services, target=None):
    for service in services:
        _find_service(service, target)


def _find_service(service, target):
    net4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    net6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    net6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    if target:
        addrs = socket.getaddrinfo(target, 1900, 0, socket.SOCK_DGRAM)
        for addr in addrs:
            host = addr[4][0]
            if addr[0] == socket.AF_INET:
                net4.sendto(smsg.format(host, service), addr[4])
            elif addr[0] == socket.AF_INET6:
                host = '[{0}]'.format(host)
                net6.sendto(smsg.format(host, service), addr[4])
    else:
        net4.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for idx in util.list_interface_indexes():
            net6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF,
                            idx)
            try:
                net6.sendto(smsg.format('[{0}]'.format(mcastv6addr), service
                                        ), (mcastv6addr, 1900, 0, 0))
            except socket.error:
                # ignore interfaces without ipv6 multicast causing error
                pass
        for i4 in util.list_ips():
            if 'broadcast' not in i4:
                continue
            addr = i4['addr']
            bcast = i4['broadcast']
            net4.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                            socket.inet_aton(addr))
            net4.sendto(smsg.format(mcastv4addr, service),
                        (mcastv4addr, 1900))
            net4.sendto(smsg.format(bcast, service), (bcast, 1900))
        r, _, _ = select.select((net4, net6), (), (), 1)
        while r:
            for s in r:
                (rsp, peer) = s.recvfrom(9000)
                print(repr(rsp))
                print(repr(peer))
            r, _, _ = select.select((net4, net6), (), (), 1)


if __name__ == '__main__':
    find_targets(['urn:dmtf-org:service:redfish-rest:1'])