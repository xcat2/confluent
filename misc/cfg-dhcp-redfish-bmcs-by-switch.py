#!/usr/bin/python3
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

# This script demonstrates a strategy for redfish bmcs that
# dhcp to leverage the confluent switch scanning to help
# bootstrap such devices. Be aware of the uuid reformatting
# code, and determine if it is relevant for the target system
# in question.  The normal thing would be to leave UUID as-is,
# but some implementations mangle it in a misunderstanding
# of 'wire format' UUID.  Also, here xCAT is used as the 
# 'dhcp helper', so that may need to be replaced with dnsmasq
# or direct isc dhcp code.

# Unfortunately, this is particular about the dhcp server,
# the user must know if the bmc in question mangles the uuid
# or not, and other such limitation make this difficult to blindly
# recommend, but hopefully can be useful reference material


import sys
sys.path.append('/opt/confluent/lib/python')
import confluent.client as cli
import eventlet.greenpool
import gzip
import io
import json
import os
import struct
import subprocess
import time

webclient = eventlet.import_patched('pyghmi.util.webclient')


bmcsbyuuid = {}
def checkfish(addr, mac):
    wc = webclient.SecureHTTPConnection(addr, 443, verifycallback=lambda x: True)
    wc.connect()
    wc.request('GET', '/redfish/v1')
    rsp = wc.getresponse()
    body = rsp.read()
    if body[:2] == b'\x1f\x8b':
        body = gzip.GzipFile(fileobj=io.BytesIO(body)).read()
    try:
        body = json.loads(body)
    except json.decoder.JSONDecodeError:
        return
    uuid = body.get('UUID', None)
    if not uuid:
        return
    #This part is needed if a bmc sticks 'wire format' uuid in the json body
    #Should be skipped for bmcs that present it sanely
    uuidparts = uuid.split('-')
    uuidparts[0] = '{:08x}'.format(struct.unpack('!I', struct.pack('<I', int(uuidparts[0], 16)))[0])
    uuidparts[1] = '{:04x}'.format(struct.unpack('!H', struct.pack('<H', int(uuidparts[1], 16)))[0])
    uuidparts[2] = '{:04x}'.format(struct.unpack('!H', struct.pack('<H', int(uuidparts[2], 16)))[0])
    uuid = '-'.join(uuidparts)
    if uuid in bmcsbyuuid:
        bmcsbyuuid[uuid]['bmcs'][mac] = addr
    else:
        bmcsbyuuid[uuid] = {'bmcs': {mac: addr}}


if __name__ == '__main__':
    gpool = eventlet.greenpool.GreenPool()
    with open('/var/lib/dhcpd/dhcpd.leases', 'r') as leasefile:
        leases = leasefile.read()
    inlease = False
    currip = None
    mactoips = {}
    for line in leases.split('\n'):
        if line.startswith('lease '):
            currip = line.split()[1]
            inlease = True
            continue
        if not inlease:
            continue
        if 'hardware ethernet' in line:
            currmac = line.split()[-1].replace(';', '')
            mactoips[currmac] = currip
            currmac = None
            currip = None
            inlease = False
    # warm up arp tables and fdb
    pings = {} 
    for mac in mactoips:
        pings[mac] = subprocess.Popen(['ping', '-c', '1', mactoips[mac]], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for mac in pings:
        ret = pings[mac].wait()
        if ret != 0:
            del mactoips[mac]
    c = cli.Command()
    list(c.update('/networking/macs/rescan', {'rescan': 'start'}))
    scanning = True
    mactonode = {}
    while scanning:
        for rsp in c.read('/networking/macs/rescan'):
            scanning = rsp.get('scanning', True)
            time.sleep(0.1)
    for mac in mactoips:
        macinfo = list(c.read('/networking/macs/by-mac/{}'.format(mac)))
        for inf in macinfo:
            if inf.get('possiblenode', None):
                mactonode[mac] = inf['possiblenode']
    for mac in sorted(mactonode):
        gpool.spawn(checkfish, mactoips[mac], mac)
    gpool.waitall()
    for uuid in sorted(bmcsbyuuid):
        macd = bmcsbyuuid[uuid]['bmcs']
        macs = sorted(macd)
        currnode = None
        for mac in macs:
            currnode = mactonode.get(mac, None)
            if currnode:
                break
        print('Performing: nodeattrib {} id.uuid={} custom.bmcmac={} bmc={}'.format(currnode, uuid, macs[0], macd[macs[0]]))
        list(c.update('/nodes/{}/attributes/current'.format(currnode), {'id.uuid': uuid, 'custom.bmcmac': macs[0], 'bmc': macd[macs[0]]}))
        subprocess.check_call(['nodeadd', currnode + '-bmc', 'mac.mac=' + macs[0]])
        subprocess.check_call(['makedhcp', currnode + '-bmc'])
        subprocess.check_call(['nodeboot', currnode])
        subprocess.check_call(['nodebmcreset', currnode])
        list(c.update('/nodes/{}/attributes/current'.format(currnode), {'bmc': currnode + '-bmc'}))

