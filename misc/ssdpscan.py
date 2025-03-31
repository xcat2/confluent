
from select import select
import socket
import sys
import socket

def scan_nicname(nicname):
    idx = int(open('/sys/class/net/{}/ifindex'.format(nicname)).read())
    return scan_nic(idx)

def scan_nic(nicidx):
    known_peers = {}
    srvs = {}
    s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s6.bind(('::', 0))
    msg = b'M-SEARCH * HTTP/1.1\r\nHOST: [ff02::c]:1900\r\nMAN: "ssdp:discover"\r\nST: urn:dmtf-org:service:redfish-rest:1\r\nMX: 3\r\n\r\n'
    s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, nicidx)
    x = [False,]
    tries=5
    s6.sendto(msg, ('ff02::c', 1900))
    x = select((s6,), (), (), 3.0)
    while x[0]:
        (rsp, peer) = s6.recvfrom(9000)
        x = select((s6,), (), (), 0.5)
        if peer in known_peers:
            continue
        known_peers[peer] = 1
        if '%' not in peer[0]:
            peer = list(peer)
            peer[0] = '{}%{}'.format(peer[0], nicidx)
        print("Received Redfish response from {}".format(peer[0]))



def main():
    scan_nicname(sys.argv[1])


if __name__ == '__main__':
    main()
