# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2017,2022 Lenovo
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

def msg_align(len):
    return (len + 3) & ~3

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

def ip_on_same_subnet(first, second, prefix):
    if first.startswith('::ffff:') and '.' in first:
        first = first.replace('::ffff:', '')
    if second.startswith('::ffff:') and '.' in second:
        second = second.replace('::ffff:', '')
    addrinf = socket.getaddrinfo(first, None, 0, socket.SOCK_STREAM)[0]
    fam = addrinf[0]
    if '%' in addrinf[-1][0]:
        return False
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


def ipn_is_local(ipn):
    if len(ipn) > 5 and ipn.startswith(b'\xfe\x80'):
        return True
    for addr in get_my_addresses():
        if len(addr[1]) != len(ipn):
            continue
        if ipn_on_same_subnet(addr[0], ipn, addr[1], addr[2]):
            return True
    return False


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
        try:
            ci = int(open('/sys/class/net/{0}/ifindex'.format(iname)).read())
            _idxtoifnamemap[ci] = iname
        except Exception:  # there may be non interface in /sys/class/net
            pass


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


def _iftonets(ifidx):
    if isinstance(ifidx, int):
        _rebuildidxmap()
        ifidx = _idxtoifnamemap.get(ifidx, None)
    return inametonets(ifidx)

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


class NetManager(object):
    def __init__(self, myaddrs, node, configmanager):
        self.myaddrs = myaddrs
        self._allmyaddrs = None
        self.cfm = configmanager
        self.node = node
        self.myattribs = {}
        self.consumednames4 = set([])
        self.consumednames6 = set([])

    @property
    def allmyaddrs(self):
        if not self._allmyaddrs:
            self._allmyaddrs = get_my_addresses()
        return self._allmyaddrs

    def process_attribs(self, netname, attribs):
        self.myattribs[netname] = {}
        ipv4addr = None
        ipv6addr = None
        myattribs = self.myattribs[netname]
        hwaddr = attribs.get('hwaddr', None)
        if hwaddr:
            myattribs['hwaddr'] = hwaddr
        conname = attribs.get('connection_name', None)
        if conname:
            myattribs['connection_name'] = conname
        iname = attribs.get('interface_names', None)
        if iname:
            myattribs['interface_names'] = iname
        teammod = attribs.get('team_mode', None)
        if teammod:
            myattribs['team_mode'] = teammod
        method = attribs.get('ipv4_method', None)
        if method != 'dhcp':
            ipv4addr = attribs.get('ipv4_address', None)
            if ipv4addr:
                try:
                    luaddr = ipv4addr.split('/', 1)[0]
                    for ai in socket.getaddrinfo(luaddr, 0, socket.AF_INET, socket.SOCK_STREAM):
                        ipv4addr.replace(luaddr, ai[-1][0])
                except socket.gaierror:
                    pass
            else:
                currname = attribs.get('hostname', self.node).split()[0]
                if currname and currname not in self.consumednames4:
                    try:
                        for ai in socket.getaddrinfo(currname, 0, socket.AF_INET, socket.SOCK_STREAM):
                            ipv4addr = ai[-1][0]
                            self.consumednames4.add(currname)
                    except socket.gaierror:
                        pass
            if ipv4addr:
                myattribs['ipv4_method'] = 'static'
                myattribs['ipv4_address'] = ipv4addr
        else:
            myattribs['ipv4_method'] = 'dhcp'
        if attribs.get('ipv4_gateway', None) and 'ipv4_method' in myattribs:
            myattribs['ipv4_gateway'] = attribs['ipv4_gateway']
        method = attribs.get('ipv6_method', None)
        if method != 'dhcp':
            ipv6addr = attribs.get('ipv6_address', None)
            if ipv6addr:
                try:
                    for ai in socket.getaddrinfo(ipv6addr, 0, socket.AF_INET6, socket.SOCK_STREAM):
                        ipv6addr = ai[-1][0]
                except socket.gaierror:
                    pass
            else:
                currname = attribs.get('hostname', self.node).split()[0]
                if currname and currname not in self.consumednames6:
                    try:
                        for ai in socket.getaddrinfo(currname, 0, socket.AF_INET6, socket.SOCK_STREAM):
                            ipv6addr = ai[-1][0]
                            self.consumednames6.add(currname)
                    except socket.gaierror:
                        pass
            if ipv6addr:
                myattribs['ipv6_method'] = 'static'
                myattribs['ipv6_address'] = ipv6addr
        else:
            myattribs['ipv6_method'] = 'dhcp'
        if attribs.get('ipv6_gateway', None) and 'ipv6_method' in myattribs:
            myattribs['ipv6_gateway'] = attribs['ipv6_gateway']
        if 'ipv4_method' not in myattribs and 'ipv6_method' not in myattribs:
            del self.myattribs[netname]
            return
        if ipv4addr:
            prefixlen = None
            if '/' in ipv4addr:
                ipv4addr, _ = ipv4addr.split('/', 1)
            ipv4bytes = socket.inet_pton(socket.AF_INET, ipv4addr.split('/')[0])
            for addr in self.myaddrs:
                if addr[0] != socket.AF_INET:
                    continue
                if ipn_on_same_subnet(addr[0], addr[1], ipv4bytes, addr[2]):
                    myattribs['current_nic'] = True
                    myattribs['ipv4_address'] = '{0}/{1}'.format(ipv4addr, addr[2])
        if not myattribs.get('current_nic', False) and ipv6addr:
            if '/' in ipv6addr:
                ipv6addr, _ = ipv6addr.split('/', 1)
            ipv6bytes = socket.inet_pton(socket.AF_INET6, ipv6addr)
            for addr in self.myaddrs:
                if addr[0] != socket.AF_INET6:
                    continue
                if ipn_on_same_subnet(addr[0], addr[1], ipv6bytes, addr[2]):
                    myattribs['current_nic'] = True
                    myattribs['ipv6_address'] = '{0}/{1}'.format(ipv6addr, addr[2])
        if '/' not in myattribs.get('ipv6_address', '/'):
            ipn = socket.inet_pton(socket.AF_INET6, myattribs['ipv6_address'])
            plen = 64
            for addr in self.allmyaddrs:
                if addr[0] != socket.AF_INET6:
                    continue
                if ipn_on_same_subnet(addr[0], ipn, addr[1], addr[2]):
                    plen = addr[2]
            myattribs['ipv6_address'] += '/{0}'.format(plen)
        if '/' not in myattribs.get('ipv4_address', '/'):
            ipn = socket.inet_pton(socket.AF_INET, myattribs['ipv4_address'])
            plen = 16
            for addr in self.allmyaddrs:
                if addr[0] != socket.AF_INET:
                    continue
                if ipn_on_same_subnet(addr[0], ipn, addr[1], addr[2]):
                    plen = addr[2]
            myattribs['ipv4_address'] += '/{0}'.format(plen)
        if 'current_nic' not in myattribs:
            myattribs['current_nic'] = False


def get_flat_net_config(configmanager, node):
    fnc = get_full_net_config(configmanager, node)
    dft = fnc.get('default', {})
    if dft:
        ret = [dft]
    else:
        ret = []
    for nc in fnc.get('extranets', {}):
        nc = fnc['extranets'][nc]
        if nc:
            ret.append(nc)
    return ret

def add_netmask(ncfg):
    if '/' in ncfg.get('ipv4_address', ''):
        plen = ncfg['ipv4_address'].split('/', 1)[1]
        ncfg['ipv4_netmask'] = cidr_to_mask(int(plen))

def get_full_net_config(configmanager, node, serverip=None):
    cfd = configmanager.get_node_attributes(node, ['net.*'])
    cfd = cfd.get(node, {})
    attribs = {}
    for attrib in cfd:
        val = cfd[attrib].get('value', None)
        if val is None:
            continue
        if attrib.startswith('net.'):
            attrib = attrib.replace('net.', '').rsplit('.', 1)
            if len(attrib) == 1:
                iface = None
                attrib = attrib[0]
            else:
                iface, attrib = attrib
            if attrib in ('switch', 'switchport', 'bootable'):
                continue
            if iface not in attribs:
                attribs[iface] = {}
            attribs[iface][attrib] = val
    myaddrs = []
    if serverip:
        myaddrs = get_addresses_by_serverip(serverip)
    nm = NetManager(myaddrs, node, configmanager)
    nnc = get_nic_config(configmanager, node, serverip=serverip)
    defaultnic = {}
    if nnc.get('ipv4_address', None):
        defaultnic['ipv4_address'] = '{}/{}'.format(nnc['ipv4_address'], nnc['prefix'])
    if nnc.get('ipv4_gateway', None):
        defaultnic['ipv4_gateway'] = nnc['ipv4_gateway']
    if nnc.get('ipv4_method', None):
        defaultnic['ipv4_method'] = nnc['ipv4_method']
    if nnc.get('ipv6_address', None):
        defaultnic['ipv6_address'] = '{}/{}'.format(nnc['ipv6_address'], nnc['ipv6_prefix'])
    if nnc.get('ipv6_method', None):
        defaultnic['ipv6_method'] = nnc['ipv6_method']
    if None in attribs:
        nm.process_attribs(None, attribs[None])
        del attribs[None]
    for netname in sorted(attribs):
        nm.process_attribs(netname, attribs[netname])
    retattrs = {}
    if None in nm.myattribs:
        retattrs['default'] = nm.myattribs[None]
        add_netmask(retattrs['default'])
        del nm.myattribs[None]
    retattrs['extranets'] = nm.myattribs
    for attri in retattrs['extranets']:
        add_netmask(retattrs['extranets'][attri])
        if retattrs['extranets'][attri].get('ipv4_address', None) == defaultnic.get('ipv4_address', 'NOPE'):
            defaultnic = {}
        if retattrs['extranets'][attri].get('ipv6_address', None) == defaultnic.get('ipv6_address', 'NOPE'):
            defaultnic = {}
    if 'default' not in retattrs and defaultnic:
        retattrs['default'] = defaultnic
        add_netmask(retattrs['default'])
        ipv4addr = defaultnic.get('ipv4_address', None)
        if '/' in ipv4addr:
            ipv4bytes = socket.inet_pton(socket.AF_INET, ipv4addr.split('/')[0])
            for addr in nm.myaddrs:
                if addr[0] != socket.AF_INET:
                    continue
                if ipn_on_same_subnet(addr[0], addr[1], ipv4bytes, addr[2]):
                    defaultnic['current_nic'] = True
        ipv6addr = defaultnic.get('ipv6_address', None)
        if '/' in ipv6addr:
            ipv6bytes = socket.inet_pton(socket.AF_INET6, ipv6addr.split('/')[0])
            for addr in nm.myaddrs:
                if addr[0] != socket.AF_INET6:
                    continue
                if ipn_on_same_subnet(addr[0], addr[1], ipv6bytes, addr[2]):
                    defaultnic['current_nic'] = True
    return retattrs


def noneify(cfgdata):
    for key in cfgdata:
        if cfgdata[key] == '':
            cfgdata[key] = None
    return cfgdata

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
        'ipv6_prefix': None,
        'ipv6_address': None,
        'ipv6_method': None,
    }
    myaddrs = []
    if ifidx is not None:
        dhcprequested = False
        myaddrs = get_my_addresses(ifidx)
        v4broken = True
        v6broken = True
        for addr in myaddrs:
            if addr[0] == socket.AF_INET:
                v4broken = False
            elif addr[0] == socket.AF_INET6:
                v6broken = False
        if v4broken:
            cfgdata['ipv4_broken'] = True
        if v6broken:
            cfgdata['ipv6_broken'] = True
    if serverip is not None:
        dhcprequested = False
        myaddrs = get_addresses_by_serverip(serverip)
    genericmethod = 'static'
    ipbynodename = None
    ip6bynodename = None
    try:
        for addr in socket.getaddrinfo(node, 0, socket.AF_INET, socket.SOCK_DGRAM):
            ipbynodename = addr[-1][0]
    except socket.gaierror:
        pass
    try:
        for addr in socket.getaddrinfo(node, 0, socket.AF_INET6, socket.SOCK_DGRAM):
                ip6bynodename = addr[-1][0]
    except socket.gaierror:
        pass
    if myaddrs:
        foundaddr = False
        candgws = []
        candsrvs = []
        bestsrvbyfam = {}
        for myaddr in myaddrs:
            fam, svrip, prefix = myaddr[:3]
            candsrvs.append((fam, svrip, prefix))
            if fam == socket.AF_INET:
                nver = '4'
                srvkey = 'deploy_server'
            elif fam == socket.AF_INET6:
                nver = '6'
                srvkey = 'deploy_server_v6'
            if fam not in bestsrvbyfam:
                cfgdata[srvkey] = socket.inet_ntop(fam, svrip)
            for candidate in cfgbyname:
                ipmethod = cfgbyname[candidate].get('ipv{}_method'.format(nver), 'static')
                if ipmethod == 'dhcp':
                    dhcprequested = True
                    continue
                if ipmethod == 'firmwaredhcp':
                    genericmethod = ipmethod
                candip = cfgbyname[candidate].get('ipv{}_address'.format(nver), None)
                if candip and '/' in candip:
                    candip, candprefix = candip.split('/')
                    if int(candprefix) != prefix:
                        continue
                candgw = cfgbyname[candidate].get('ipv{}_gateway'.format(nver), None)
                if candip:
                    try:
                        for inf in socket.getaddrinfo(candip, 0, fam, socket.SOCK_STREAM):
                            candipn = socket.inet_pton(fam, inf[-1][0])
                        if ipn_on_same_subnet(fam, svrip, candipn, prefix):
                            bestsrvbyfam[fam] = svrip
                            cfgdata['ipv{}_address'.format(nver)] = candip
                            cfgdata['ipv{}_method'.format(nver)] = ipmethod
                            cfgdata['ipv{}_gateway'.format(nver)] = cfgbyname[candidate].get(
                                'ipv{}_gateway'.format(nver), None)
                            if nver == '4':
                                cfgdata['prefix'] = prefix
                            else:
                                cfgdata['ipv{}_prefix'.format(nver)] = prefix
                            if candip in (ipbynodename, ip6bynodename):
                                cfgdata['matchesnodename'] = True
                            foundaddr = True
                    except Exception as e:
                        cfgdata['error_msg'] = "Error trying to evaluate net.*ipv4_address attribute value '{0}' on {1}: {2}".format(candip, node, str(e))
                elif candgw:
                    for inf in socket.getaddrinfo(candgw, 0, fam, socket.SOCK_STREAM):
                        candgwn = socket.inet_pton(fam, inf[-1][0])
                    if ipn_on_same_subnet(fam, svrip, candgwn, prefix):
                        candgws.append((fam, candgwn, prefix))
        if foundaddr:
            return noneify(cfgdata)
        if dhcprequested:
            if not cfgdata.get('ipv4_method', None):
                cfgdata['ipv4_method'] = 'dhcp'
            if not cfgdata.get('ipv6_method', None):
                cfgdata['ipv6_method'] = 'dhcp'
            return noneify(cfgdata)
        if ipbynodename == None and ip6bynodename == None:
            return noneify(cfgdata)
        for myaddr in myaddrs:
            fam, svrip, prefix = myaddr[:3]
            if fam == socket.AF_INET:
                bynodename = ipbynodename
                nver = '4'
            else:
                bynodename = ip6bynodename
                nver = '6'
            if not bynodename:  # node is missing either ipv6 or ipv4, ignore
                continue
            ipbynodenamn = socket.inet_pton(fam, bynodename)
            if ipn_on_same_subnet(fam, svrip, ipbynodenamn, prefix):
                cfgdata['matchesnodename'] = True
                cfgdata['ipv{}_address'.format(nver)] = bynodename
                cfgdata['ipv{}_method'.format(nver)] = genericmethod
                if nver == '4':
                    cfgdata['prefix'] = prefix
                else:
                    cfgdata['ipv{}_prefix'.format(nver)] = prefix
        for svr in candsrvs:
            fam, svr, prefix = svr
            if fam == socket.AF_INET:
                bynodename = ipbynodename
            elif fam == socket.AF_INET6:
                bynodename = ip6bynodename
            if not bynodename:
                continue  # ignore undefined family
            bynodenamn = socket.inet_pton(fam, bynodename)
            if ipn_on_same_subnet(fam, svr, bynodenamn, prefix):
                svrname = socket.inet_ntop(fam, svr)
                if fam == socket.AF_INET:
                    cfgdata['deploy_server'] = svrname
                else:
                    cfgdata['deploy_server_v6'] = svrname
        for gw in candgws:
            fam, candgwn, prefix = gw
            if fam == socket.AF_INET:
                nver = '4'
                bynodename = ipbynodename
            elif fam == socket.AF_INET6:
                nver = '6'
                bynodename = ip6bynodename
            if bynodename:
                bynodenamn = socket.inet_pton(fam, bynodename)
                if ipn_on_same_subnet(fam, candgwn, bynodenamn, prefix):
                    cfgdata['ipv{}_gateway'.format(nver)] = socket.inet_ntop(fam, candgwn)
        return noneify(cfgdata)
    if ip is not None:
        for prefixinfo in get_prefix_len_for_ip(ip):
            fam, prefix = prefixinfo
            ip = ip.split('/', 1)[0]
            if fam == socket.AF_INET:
                cfgdata['prefix'] = prefix
                nver = '4'
            else:
                nver = '6'
                cfgdata['ipv{}_prefix'.format(nver)] = prefix
            for setting in nodenetattribs:
                if 'ipv{}_gateway'.format(nver) not in setting:
                    continue
                gw = nodenetattribs[setting].get('value', None)
                if gw is None or not gw:
                    continue
                gwn = socket.inet_pton(fam, gw)
                ip = socket.getaddrinfo(ip, 0, proto=socket.IPPROTO_TCP, family=fam)[-1][-1][0]
                ipn = socket.inet_pton(fam, ip)
                if ipn_on_same_subnet(fam, ipn, gwn, prefix):
                    cfgdata['ipv{}_gateway'.format(nver)] = gw
                    break
    return noneify(cfgdata)

def get_addresses_by_serverip(serverip):
    if '.' in serverip:
        fam = socket.AF_INET
    elif ':' in serverip:
        fam = socket.AF_INET6
    else:
        raise ValueError('"{0}" is not a valid ip argument')
    ipbytes = socket.inet_pton(fam, serverip)
    if ipbytes[:8] == b'\xfe\x80\x00\x00\x00\x00\x00\x00':
        myaddrs = get_my_addresses(matchlla=ipbytes)
    else:
        myaddrs = [x for x in get_my_addresses() if x[1] == ipbytes]
    return myaddrs

nlhdrsz = struct.calcsize('IHHII')
ifaddrsz = struct.calcsize('BBBBI')

def get_my_addresses(idx=0, family=0, matchlla=None):
    # RTM_GETADDR = 22
    # nlmsghdr struct: u32 len, u16 type, u16 flags, u32 seq, u32 pid
    nlhdr = struct.pack('IHHII', nlhdrsz + ifaddrsz, 22, 0x301, 0, 0)
    # ifaddrmsg struct: u8 family, u8 prefixlen, u8 flags, u8 scope, u32 index
    ifaddrmsg = struct.pack('BBBBI', family, 0, 0, 0, idx)
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    s.bind((0, 0))
    s.sendall(nlhdr + ifaddrmsg)
    addrs = []
    while True:
        pdata = s.recv(65536)
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
                                return get_my_addresses(idx=ridx)
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
    return addrs


def get_prefix_len_for_ip(ip):
    plen = None
    if '/' in ip:
        ip, plen = ip.split('/', 1)
        plen = int(plen)
    myaddrs = get_my_addresses()
    found = False
    for inf in socket.getaddrinfo(ip, 0, 0, socket.SOCK_DGRAM):
        if plen:
            yield (inf[0], plen)
            return
        for myaddr in myaddrs:
            if inf[0] != myaddr[0]:
                continue
            if ipn_on_same_subnet(myaddr[0], myaddr[1], socket.inet_pton(myaddr[0], inf[-1][0]), myaddr[2]):
                found = True
                yield (myaddr[0], myaddr[2])
    if not found:
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
    if '%' in addr1 or '%' in addr2:
        return False
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
