# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2016-2017 Lenovo
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

# This provides the implementation of locating MAC addresses on ethernet
# switches.  It is, essentially, a port of 'MacMap.pm' to confluent.
# However, there are enhancements.
# For one, each switch interrogation is handled in an eventlet 'thread'
# For another, MAC addresses are checked in the dictionary on every
# switch return, rather than waiting for all switches to check in
# (which makes it more responsive when there is a missing or bad switch)
# Also, we track the quantity, actual ifName value, and provide a mechanism
# to detect ambiguous result (e.g. if two matches are found, can log an error
# rather than doing the wrong one, complete with the detected ifName value).
# Further, the map shall be available to all facets of the codebase, not just
# the discovery process, so that the cached data maintenance will pay off
# for direct queries

# this module will provide mac to switch and full 'ifName' label
# This functionality is restricted to the null tenant

if __name__ == '__main__':
    import sys
    import confluent.config.configmanager as cfm
import confluent.exceptions as exc
import confluent.log as log
import confluent.snmputil as snmp
import confluent.util as util
from eventlet.greenpool import GreenPool
import eventlet
import eventlet.semaphore
import re

_macmap = {}
_macsbyswitch = {}
_nodesbymac = {}
_switchportmap = {}
vintage = None


_whitelistnames = (
    # 3com
    re.compile(r'^RMON Port (\d+) on unit \d+'),
    # Dell
    re.compile(r'^Unit \d+ Port (\d+)\Z'),
)

_blacklistnames = (
    re.compile(r'vl'),
    re.compile(r'Nu'),
    re.compile(r'RMON'),
    re.compile(r'onsole'),
    re.compile(r'Stack'),
    re.compile(r'Trunk'),
    re.compile(r'po\d'),
    re.compile(r'XGE'),
    re.compile(r'LAG'),
    re.compile(r'CPU'),
    re.compile(r'Management'),
)


def _namesmatch(switchdesc, userdesc):
    if switchdesc == userdesc:
        return True
    try:
        portnum = int(userdesc)
    except ValueError:
        portnum = None
    if portnum is not None:
        for exp in _whitelistnames:
            match = exp.match(switchdesc)
            if match:
                snum = int(match.groups()[0])
                if snum == portnum:
                    return True
    anymatch = re.search(r'[^0123456789]' + userdesc + r'(\.0)?\Z', switchdesc)
    if anymatch:
        for blexp in _blacklistnames:
            if blexp.match(switchdesc):
                return False
        return True
    return False

def _map_switch(args):
    try:
        return _map_switch_backend(args)
    except UnicodeError:
        log.log({'error': "Cannot resolve switch '{0}' to an address".format(
            args[0])})
    except exc.TargetEndpointUnreachable:
        log.log({'error': "Timeout or bad SNMPv1 community string trying to "
                         "reach switch '{0}'".format(
            args[0])})
    except exc.TargetEndpointBadCredentials:
        log.log({'error': "Bad SNMPv3 credentials for \'{0}\'".format(
            args[0])})
    except Exception as e:
        log.log({'error': 'Unexpected condition trying to reach switch "{0}"'
                          ' check trace log for more'.format(args[0])})
        log.logtrace()


def _nodelookup(switch, ifname):
    """Get a nodename for a given switch and interface name
    """
    for portdesc in _switchportmap.get(switch, {}):
        if _namesmatch(ifname, portdesc):
            return _switchportmap[switch][portdesc]
    return None


def _map_switch_backend(args):
    """Manipulate portions of mac address map relevant to a given switch
    """

    # 1.3.6.1.2.1.17.7.1.2.2.1.2 - mactoindex (qbridge - preferred)
    #  if not, check for cisco and if cisco, build list of all relevant vlans:
    #  .1.3.6.1.4.1.9.9.46.1.6.1.1.5 - trunk port vlan map (cisco only)
    #  .1.3.6.1.4.1.9.9.68.1.2.2.1.2 - access port vlan map (cisco only)
    # if cisco, vlan community string indexed or snmpv3 contest for:
    # 1.3.6.1.2.1.17.4.3.1.2 - mactoindx (bridge - low-end switches and cisco)
    #     .1.3.6.1.2.1.17.1.4.1.2 - bridge index to if index map
    # no vlan index or context for:
    #  .1.3.6.1.2.1.31.1.1.1.1 - ifName... but some switches don't do it
    #  .1.3.6.1.2.1.2.2.1.2 - ifDescr, usually useless, but a
    #   fallback if ifName is empty
    #
    global _macmap
    if len(args) == 3:
        switch, password, user = args
        if not user:
            user = None
    else:
        switch, password = args
        user = None
    haveqbridge = False
    mactobridge = {}
    conn = snmp.Session(switch, password, user)
    for vb in conn.walk('1.3.6.1.2.1.17.7.1.2.2.1.2'):
        haveqbridge = True
        oid, bridgeport = vb
        if not bridgeport:
            continue
        oid = str(oid).rsplit('.', 6)  # if 7, then oid[1] would be vlan id
        macaddr = '{0:02x}:{1:02x}:{2:02x}:{3:02x}:{4:02x}:{5:02x}'.format(
            *([int(x) for x in oid[-6:]])
        )
        mactobridge[macaddr] = int(bridgeport)
    if not haveqbridge:
        raise exc.NotImplementedException('TODO: Bridge-MIB without QBRIDGE')
    bridgetoifmap = {}
    for vb in conn.walk('1.3.6.1.2.1.17.1.4.1.2'):
        bridgeport, ifidx = vb
        bridgeport = int(str(bridgeport).rsplit('.', 1)[1])
        bridgetoifmap[bridgeport] = int(ifidx)
    ifnamemap = {}
    havenames = False
    for vb in conn.walk('1.3.6.1.2.1.31.1.1.1.1'):
        ifidx, ifname = vb
        if not ifname:
            continue
        havenames = True
        ifidx = int(str(ifidx).rsplit('.', 1)[1])
        ifnamemap[ifidx] = str(ifname)
    if not havenames:
        for vb in conn.walk( '1.3.6.1.2.1.2.2.1.2'):
            ifidx, ifname = vb
            ifidx = int(str(ifidx).rsplit('.', 1)[1])
            ifnamemap[ifidx] = str(ifname)
    maccounts = {}
    for mac in mactobridge:
        ifname = ifnamemap[bridgetoifmap[mactobridge[mac]]]
        if ifname not in maccounts:
            maccounts[ifname] = 1
        else:
            maccounts[ifname] += 1
    _macsbyswitch[switch] = {}
    for mac in mactobridge:
        # We want to merge it so that when a mac appears in multiple
        # places, it is captured.
        ifname = ifnamemap[bridgetoifmap[mactobridge[mac]]]
        if mac in _macmap:
            _macmap[mac].append((switch, ifname, maccounts[ifname]))
        else:
            _macmap[mac] = [(switch, ifname, maccounts[ifname])]
        if ifname in _macsbyswitch[switch]:
            _macsbyswitch[switch][ifname].append(mac)
        else:
            _macsbyswitch[switch][ifname] = [mac]
        nodename = _nodelookup(switch, ifname)
        if nodename is not None:
            if mac in _nodesbymac and _nodesbymac[mac] != nodename:
                # For example, listed on both a real edge port
                # and by accident a trunk port
                log.log({'error': '{0} and {1} described by ambiguous'
                                    ' switch topology values'.format(nodename,
                                                              _nodesbymac[mac]
                                                              )})
                _nodesbymac[mac] = None
            else:
                _nodesbymac[mac] = nodename


def find_node_by_mac(mac, configmanager):
    now = util.monotonic_time()
    if vintage and now - vintage < 90 and mac in _nodesbymac:
        return _nodesbymac[mac]
    # do not actually sweep switches more than once every 10 seconds
    # however, if there is an update in progress, wait on it
    for _ in update_macmap(configmanager, vintage and now - vintage < 10):
        if mac in _nodesbymac:
            return _nodesbymac[mac]
    # If update_mac bailed out, still check one last time
    return _nodesbymac.get(mac, None)


mapupdating = eventlet.semaphore.Semaphore()


def update_macmap(configmanager, impatient=False):
    """Interrogate switches to build/update mac table

    Begin a rebuild process.  This process is a generator that will yield
    as each switch interrogation completes, allowing a caller to
    recheck the cache as results become possible, rather
    than having to wait for the process to complete to interrogate.
    """
    global _macmap
    global _nodesbymac
    global _switchportmap
    global vintage
    if mapupdating.locked():
        while mapupdating.locked():
            eventlet.sleep(1)
            yield None
        return
    if impatient:
        return
    with mapupdating:
        vintage = util.monotonic_time()
        # Clear all existing entries
        _macmap = {}
        _nodesbymac = {}
        _switchportmap = {}
        if configmanager.tenant is not None:
            raise exc.ForbiddenRequest(
                'Network topology not available to tenants')
        nodelocations = configmanager.get_node_attributes(
            configmanager.list_nodes(), ('net.switch', 'net.switchport'))
        switches = set([])
        for node in nodelocations:
            cfg = nodelocations[node]
            if 'net.switch' in cfg and 'value' in cfg['net.switch']:
                curswitch = cfg['net.switch']['value']
                switches.add(curswitch)
                if 'net.switchport' in cfg:
                    portname = cfg['net.switchport']['value']
                    if curswitch not in _switchportmap:
                        _switchportmap[curswitch] = {}
                    if portname in _switchportmap[curswitch]:
                        log.log({'error': 'Duplicate switch topology config '
                                          'for {0} and {1}'.format(
                                            node,
                                            _switchportmap[curswitch][
                                                portname])})
                        _switchportmap[curswitch][portname] = None
                    else:
                        _switchportmap[curswitch][portname] = node
        switchcfg = configmanager.get_node_attributes(
            switches, ('secret.hardwaremanagementuser',
                       'secret.hardwaremanagementpassword'), decrypt=True)
        switchauth = []
        for switch in switches:
            if not switch:
                continue
            password = 'public'
            user = None
            if (switch in switchcfg and
                    'secret.hardwaremanagementpassword' in switchcfg[switch]):
                password = switchcfg[
                    switch]['secret.hardwaremanagementpassword']['value']
                if 'secret.hardwaremanagementuser' in switchcfg[switch]:
                    user = switchcfg[switch]['secret.hardwaremanagementuser'][
                        'value']
            switchauth.append((switch, password, user))
        pool = GreenPool()
        for ans in pool.imap(_map_switch, switchauth):
            yield ans


if __name__ == '__main__':
    cg = cfm.ConfigManager(None)
    for res in update_macmap(cg):
        print("map has updated")
    if len(sys.argv) > 1:
        print(repr(_macmap[sys.argv[1]]))
        print(repr(_nodesbymac[sys.argv[1]]))
    else:
        print("Mac to Node lookup table: -------------------")
        print(repr(_nodesbymac))
        print("Mac to location lookup table: -------------------")
        print(repr(_macmap))
        print("switch to fdb lookup table: -------------------")
        print(repr(_macsbyswitch))