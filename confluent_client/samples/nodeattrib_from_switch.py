#!/usr/bin/env python

# This is a sample python script for going through all observed mac addresses
# and assuming they are BMC related and printing nodeattrib commands
# for each node to access the bmc using the interface specified on the command
# line

# Not necessarily as useful if there may be mistakes in the
# net.switch/net.switchport attributes, but a handy utility in a pinch when
# you really know


import confluent.client as cl
import socket
import struct
c = cl.Command()
macs = []
interface = sys.argv[1]
for mac in c.read('/networking/macs/by-mac/'):
    macs.append(mac['item']['href'])
for mac in macs:
    macinfo = list(c.read('/networking/macs/by-mac/{0}'.format(mac)))[0]
    if 'possiblenode' in macinfo and macinfo['possiblenode']:
        if macinfo['macsonport'] > 1:
            print('#Ambiguous set of macs on port for ' + macinfo[
                'possiblenode'])
        prefix = int(mac.replace('-', '')[:6], 16) ^ 0b100000000000000000
        prefix = prefix << 8
        prefix |= 0xff
        suffix = int(mac.replace('-', '')[6:], 16)
        suffix |= 0xfe000000
        rawn = struct.pack('!QLL', 0xfe80000000000000, prefix, suffix)
        bmc = socket.inet_ntop(socket.AF_INET6, rawn)
        print('nodeattrib {0} bmc={1}%{2}'.format(macinfo['possiblenode'],
                                                  bmc, interface))
