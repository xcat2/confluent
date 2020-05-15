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


import confluent.exceptions as exc
import codecs
import netifaces
import struct
import eventlet.green.socket as socket
import eventlet.support.greendns
import os
getaddrinfo = eventlet.support.greendns.getaddrinfo


def mask_to_cidr(mask):
    maskn = socket.inet_pton(socket.AF_INET, mask)
    maskn = struct.unpack('!I', maskn)[0]
    cidr = 32
    while maskn & 0b1 == 0 and cidr > 0:
        cidr -= 1
        maskn >>= 1
    return cidr

def cidr_to_mask(cidr):
    return socket.inet_ntop(
        socket.AF_INET, struct.pack('!I', (2**32 - 1) ^ (2**(32 - cidr) - 1)))

def ip_on_same_subnet(first, second, prefix):
    if first.startswith('::ffff:') and '.' in first:
        first = first.replace('::ffff:', '')
    if second.startswith('::ffff:') and '.' in second:
        second = second.replace('::ffff:', '')
    addrinf = socket.getaddrinfo(first, None, 0, socket.SOCK_STREAM)[0]
    fam = addrinf[0]
    ip = socket.inet_pton(fam, addrinf[-1][0])
    ip = int(codecs.encode(bytes(ip), 'hex'), 16)
    addrinf = socket.getaddrinfo(second, None, 0, socket.SOCK_STREAM)[0]
    if fam != addrinf[0]:
        return False
    txtaddr = addrinf[-1][0].split('%')[0]
    oip = socket.inet_pton(fam, txtaddr)
    oip = int(codecs.encode(bytes(oip), 'hex'), 16)
    if fam == socket.AF_INET:
        addrlen = 32
    elif fam == socket.AF_INET6:
        addrlen = 128
    else:
        raise Exception("Unknown address family {0}".format(fam))
    mask = 2 ** prefix - 1 << (addrlen - prefix)
    return ip & mask == oip & mask


def address_is_local(address):
    for iface in netifaces.interfaces():
        for i4 in netifaces.ifaddresses(iface).get(2, []):
            cidr = mask_to_cidr(i4['netmask'])
            if ip_on_same_subnet(i4['addr'], address, cidr):
                return True
        for i6 in netifaces.ifaddresses(iface).get(10, []):
            cidr = int(i6['netmask'].split('/')[1])
            laddr = i6['addr'].split('%')[0]
            if ip_on_same_subnet(laddr, address, cidr):
                return True
    return False


_idxtoifnamemap = {}
def _rebuildidxmap():
    _idxtoifnamemap.clear()
    for iname in os.listdir('/sys/class/net'):
        ci = int(open('/sys/class/net/{0}/ifindex'.format(iname)).read())
        _idxtoifnamemap[ci] = iname


def myiptonets(svrip):
    fam = netifaces.AF_INET
    if ':' in svrip:
        fam = netifaces.AF_INET6
    relevantnic = None
    for iface in netifaces.interfaces():
        for addr in netifaces.ifaddresses(iface).get(fam, []):
            addr = addr.get('addr', '')
            addr = addr.split('%')[0]
            if addresses_match(addr, svrip):
                relevantnic = iface
                break
        else:
            continue
        break
    return inametonets(relevantnic)


def idxtonets(ifidx):
    _rebuildidxmap()
    iname = _idxtoifnamemap.get(ifidx, None)
    return inametonets(iname)

def inametonets(iname):
    addrs = netifaces.ifaddresses(iname)
    try:
        addrs = addrs[netifaces.AF_INET]
    except KeyError:
        return
    for addr in addrs:
        ip = struct.unpack('!I', socket.inet_aton(addr['addr']))[0]
        mask = struct.unpack('!I', socket.inet_aton(addr['netmask']))[0]
        net = ip & mask
        net = socket.inet_ntoa(struct.pack('!I', net))
        yield (net, mask_to_cidr(addr['netmask']), addr['addr'])

# TODO(jjohnson2): have a method to arbitrate setting methods, to aid
# in correct matching of net.* based on parameters, mainly for pxe
# The scheme for pxe:
# For one: the candidate net.* should have pxe set to true, to help
# disambiguate from interfaces meant for bmc access
# bmc relies upon hardwaremanagement.manager, plus we don't collect
# that mac address
# the ip as reported by recvmsg to match the subnet of that net.* interface
# if switch and port available, that should match.
def get_nic_config(configmanager, node, ip=None, mac=None, ifidx=None,
                   serverip=None):
    """Fetch network configuration parameters for a nic

    For a given node and interface, find and retrieve the pertinent network
    configuration data.  The desired configuration can be searched
    either by ip or by mac.

    :param configmanager: The relevant confluent.config.ConfigManager
        instance.
    :param node:  The name of the node
    :param ip:  An IP address on the intended subnet
    :param mac: The mac address of the interface
    :param ifidx: The local index relevant to the network.

    :returns: A dict of parameters, 'ipv4_gateway', ....
    """
    # ip parameter *could* be the result of recvmsg with cmsg to tell
    # pxe *our* ip address, or it could be the desired ip address
    #TODO(jjohnson2): ip address, prefix length, mac address,
    # join a bond/bridge, vlan configs, etc.
    # also other nic criteria, physical location, driver and index...
    nodenetattribs = configmanager.get_node_attributes(
        node, 'net*').get(node, {})
    cfgbyname = {}
    for attrib in nodenetattribs:
        segs = attrib.split('.')
        if len(segs) == 2:
            name = None
        else:
            name = segs[1]
        if name not in cfgbyname:
            cfgbyname[name] = {}
        cfgbyname[name][segs[-1]] = nodenetattribs[attrib].get('value',
                                                                None)
    cfgdata = {
        'ipv4_gateway': None,
        'ipv4_address': None,
        'ipv4_method': None,
        'prefix': None,
        'ipv4_server': None,
    }
    nets = None
    needsvrip = False
    if ifidx is not None:
        dhcprequested = False
        nets = list(idxtonets(ifidx))
    if serverip is not None:
        needsvrip = True
        dhcprequested = False
        nets = list(myiptonets(serverip))
    if nets is not None:
        candgws = []
        candsrvs = []
        for net in nets:
            net, prefix, svrip = net
            candsrvs.append(svrip)
            cfgdata['ipv4_server'] = svrip
            cfgdata['mgt_server'] = svrip
            for candidate in cfgbyname:
                if cfgbyname[candidate].get('ipv4_method', None) == 'dhcp':
                    dhcprequested = True
                    continue
                candip = cfgbyname[candidate].get('ipv4_address', None)
                if candip and '/' in candip:
                    candip, candprefix = candip.split('/')
                    if int(candprefix) != prefix:
                        continue
                candgw = cfgbyname[candidate].get('ipv4_gateway', None)
                if candip:
                    if ip_on_same_subnet(net, candip, prefix):
                        cfgdata['ipv4_address'] = candip
                        cfgdata['ipv4_method'] = 'static'
                        cfgdata['ipv4_gateway'] = cfgbyname[candidate].get(
                            'ipv4_gateway', None)
                        cfgdata['prefix'] = prefix
                        return cfgdata
                elif candgw:
                    if ip_on_same_subnet(net, candgw, prefix):
                        candgws.append(candgw)
        if dhcprequested:
            return cfgdata
        ipbynodename = None
        try:
            ipbynodename = socket.getaddrinfo(
                node, 0, socket.AF_INET, socket.SOCK_DGRAM)[0][-1][0]
        except Exception:
            return cfgdata
        for net in nets:
            net, prefix, svrip = net
            if ip_on_same_subnet(net, ipbynodename, prefix):
                cfgdata['ipv4_address'] = ipbynodename
                cfgdata['ipv4_method'] = 'static'
                cfgdata['prefix'] = prefix
                break
        for svr in candsrvs:
            if ip_on_same_subnet(svr, ipbynodename, prefix):
                cfgdata['ipv4_server'] = svr
                break
        for gw in candgws:
            if ip_on_same_subnet(gw, ipbynodename, prefix):
                cfgdata['ipv4_gateway'] = gw
                break
        return cfgdata
    if ip is not None:
        prefixlen = get_prefix_len_for_ip(ip)
        cfgdata['prefix'] = prefixlen
        for setting in nodenetattribs:
            if 'ipv4_gateway' not in setting:
                continue
            gw = nodenetattribs[setting].get('value', None)
            if gw is None or not gw:
                continue
            if ip_on_same_subnet(ip, gw, prefixlen):
                cfgdata['ipv4_gateway'] = gw
                break
    return cfgdata


def get_prefix_len_for_ip(ip):
    # for now, we'll use the system route table
    # later may provide for configuration lookup to override the route
    # table
    ip = getaddrinfo(ip, 0, socket.AF_INET)[0][-1][0]
    try:
        ipn = socket.inet_aton(ip)
    except socket.error:  # For now, assume 64 for ipv6
        return 64
    # It comes out big endian, regardless of host arch
    ipn = struct.unpack('>I', ipn)[0]
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
        # don't have big endian to look at, assume that it is host endian
        maskn = struct.unpack('I', struct.pack('>I', int(rd[7], 16)))[0]
        netn = struct.unpack('I', struct.pack('>I', int(rd[1], 16)))[0]
        if ipn & maskn == netn:
            nbits = 0
            while maskn:
                nbits += 1
                maskn = maskn << 1 & 0xffffffff
            return nbits
    raise exc.NotImplementedException("Non local addresses not supported")

def addresses_match(addr1, addr2):
    """Check two network addresses for similarity

    Is it zero padded in one place, not zero padded in another?  Is one place by name and another by IP??
    Is one context getting a normal IPv4 address and another getting IPv4 in IPv6 notation?
    This function examines the two given names, performing the required changes to compare them for equivalency

    :param addr1:
    :param addr2:
    :return: True if the given addresses refer to the same thing
    """
    for addrinfo in socket.getaddrinfo(addr1, 0, 0, socket.SOCK_STREAM):
        rootaddr1 = socket.inet_pton(addrinfo[0], addrinfo[4][0])
        if addrinfo[0] == socket.AF_INET6 and rootaddr1[:12] == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff':
            # normalize to standard IPv4
            rootaddr1 = rootaddr1[-4:]
        for otherinfo in socket.getaddrinfo(addr2, 0, 0, socket.SOCK_STREAM):
            otheraddr = socket.inet_pton(otherinfo[0], otherinfo[4][0])
            if otherinfo[0] == socket.AF_INET6 and otheraddr[:12] == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff':
                otheraddr = otheraddr[-4:]
            if otheraddr == rootaddr1:
                return True
    return False
