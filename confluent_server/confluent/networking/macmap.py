# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2016-2021 Lenovo
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

import os
import sys

if __name__ == '__main__':
    path = os.path.dirname(os.path.realpath(__file__))
    path = os.path.realpath(os.path.join(path, '..', '..'))
    if path.startswith('/opt'):
        sys.path.append(path)
    import confluent.config.configmanager as cfm
    import confluent.snmputil as snmp

import asyncio
from confluent.networking.lldp import _handle_neighbor_query, get_fingerprint
from confluent.networking.netutil import get_switchcreds, list_switches, get_portnamemap
import eventlet.green.select as select

import socket

import confluent.collective.manager as collective
import confluent.exceptions as exc
import confluent.log as log
import confluent.messages as msg
import confluent.noderange as noderange
import confluent.util as util
import eventlet.green.subprocess as subprocess
import fcntl
import eventlet
import eventlet.semaphore
import msgpack
import random
import re
import aiohmi.util.webclient as webclient


noaffluent = set([])

_macmap = {}
_apimacmap = {}
_macsbyswitch = {}
_nodesbymac = {}
_switchportmap = {}
_offloadevts = {}
_offloader = None
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
    if switchdesc is None:
        return False
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

async def _map_switch(args):
    try:
        return await _map_switch_backend(args)
    except (UnicodeError, socket.gaierror):
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


async def _affluent_map_switch(args):
    switch, password, user, cfgm = args
    kv = util.TLSCertVerifier(cfgm, switch,
                                  'pubkeys.tls_hardwaremanager').verify_cert
    wc =  webclient.WebConnection(
                switch, 443, verifycallback=kv, timeout=5)
    wc.set_basic_credentials(user, password)
    macs, retcode = wc.grab_json_response_with_status('/affluent/macs/by-port')
    if retcode != 200:
        raise Exception("No affluent detected")
    _macsbyswitch[switch] = macs

    for iface in macs:
        nummacs = len(macs[iface])
        for mac in macs[iface]:
            if mac in _macmap:
                _macmap[mac].append((switch, iface, nummacs))
            else:
                _macmap[mac] = [(switch, iface, nummacs)]
            nodename = _nodelookup(switch, iface)
            if nodename is not None:
                if mac in _nodesbymac and _nodesbymac[mac][0] != nodename:
                    # For example, listed on both a real edge port
                    # and by accident a trunk port
                    onummacs = _nodesbymac[mac][1]
                    onode = _nodesbymac[mac][0]
                    if onode:
                        errstr = 'Mac address {2} may match either {0} or {1} according to net.*switch* attributes.'.format(nodename, onode, mac)
                        if onummacs > 2 or nummacs > 2:
                            errstr += ' ({0} may match a switch trunk)'.format(nodename if nummacs > onummacs else onode)
                    else:
                        errstr = 'Mac address {1} may match either {0} or a node previously reported as ambiguous according to net.*switch* attributes.'.format(nodename, mac)
                        if nummacs > 2:
                            errstr += ' ({0} may match a switch trunk)'.format(nodename)
                    log.log({'error': errstr})
                    _nodesbymac[mac] = (None, None)
                else:
                    _nodesbymac[mac] = (nodename, nummacs)

def _offload_map_switch(switch, password, user):
    if _offloader is None:
        _start_offloader()
    evtid = random.randint(0, 4294967295)
    while evtid in _offloadevts:
        evtid = random.randint(0, 4294967295)
    _offloadevts[evtid] = eventlet.Event()
    _offloader.stdin.write(msgpack.packb((evtid, switch, password, user),
                                         use_bin_type=True))
    _offloader.stdin.flush()
    result = _offloadevts[evtid].wait()
    del _offloadevts[evtid]
    if len(result) == 2:
        if result[0] == 1:
            raise exc.deserialize_exc(result[1])
        elif result[0] == 2:
            raise Exception(result[1])
    return result



def _start_offloader():
    global _offloader
    _offloader = subprocess.Popen(
        [sys.executable, __file__, '-o'], bufsize=0, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE)
    fl = fcntl.fcntl(_offloader.stdout.fileno(), fcntl.F_GETFL)
    fcntl.fcntl(_offloader.stdout.fileno(),
                fcntl.F_SETFL, fl | os.O_NONBLOCK)
    eventlet.spawn_n(_recv_offload)
    eventlet.sleep(0)


def _recv_offload():
    try:
        upacker = msgpack.Unpacker(encoding='utf8')
    except TypeError:
        upacker = msgpack.Unpacker(raw=False, strict_map_key=False)
    instream = _offloader.stdout.fileno()
    while True:
        select.select([_offloader.stdout], [], [])
        upacker.feed(os.read(instream, 128))
        for result in upacker:
            if result[0] not in _offloadevts:
                print("Uh oh, unexpected event id... " + repr(result))
                continue
            _offloadevts[result[0]].send(result[1:])
            eventlet.sleep(0)


async def _map_switch_backend(args):
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
    if len(args) == 4:
        switch, password, user, _ = args  # 4th arg is for affluent only
        if not user:
            user = None
    else:
        switch, password = args
        user = None
    if switch not in noaffluent:
        try:
            return await _affluent_map_switch(args)
        except exc.PubkeyInvalid:
            log.log({'error': 'While trying to gather ethernet mac addresses '
                              'from {0}, the TLS certificate failed validation. '
                              'Clear pubkeys.tls_hardwaremanager if this was '
                              'expected due to reinstall or new certificate'.format(switch)})
        except Exception:
            pass
    mactobridge, ifnamemap, bridgetoifmap = _offload_map_switch(
        switch, password, user)
    maccounts = {}
    bridgetoifvalid = False
    for mac in mactobridge:
        try:
            ifname = ifnamemap[bridgetoifmap[mactobridge[mac]]]
            bridgetoifvalid = True
        except KeyError:
            continue
        if ifname not in maccounts:
            maccounts[ifname] = 1
        else:
            maccounts[ifname] += 1
    if not bridgetoifvalid:
        bridgetoifmap = {}
    # Not a single mac address resolved to an interface index, chances are
    # that the switch is broken, and the mactobridge is reporting ifidx
    # instead of bridge port index
    # try again, skipping the bridgetoifmap lookup
        for mac in mactobridge:
            try:
                ifname = ifnamemap[mactobridge[mac]]
                bridgetoifmap[mactobridge[mac]] = mactobridge[mac]
            except KeyError:
                continue
            if ifname not in maccounts:
                maccounts[ifname] = 1
            else:
                maccounts[ifname] += 1
    newmacs = {}
    noaffluent.add(switch)
    for mac in mactobridge:
        # We want to merge it so that when a mac appears in multiple
        # places, it is captured.
        try:
            ifname = ifnamemap[bridgetoifmap[mactobridge[mac]]]
        except KeyError:
            continue
        if mac in _macmap:
            _macmap[mac].append((switch, ifname, maccounts[ifname]))
        else:
            _macmap[mac] = [(switch, ifname, maccounts[ifname])]
        if ifname in newmacs:
            newmacs[ifname].append(mac)
        else:
            newmacs[ifname] = [mac]
        nodename = _nodelookup(switch, ifname)
        if nodename is not None:
            if mac in _nodesbymac and _nodesbymac[mac][0] != nodename:
                # For example, listed on both a real edge port
                # and by accident a trunk port
                nummacs = maccounts[ifname]
                onummacs = _nodesbymac[mac][1]
                onode = _nodesbymac[mac][0]
                if onode:
                    errstr = 'Mac address {2} may match either {0} or {1} according to net.*switch* attributes.'.format(nodename, onode, mac)
                    if onummacs > 2 or nummacs > 2:
                        errstr += ' ({0} may match a link between switches)'.format(nodename if nummacs > onummacs else onode)
                else:
                    errstr = 'Mac address {1} may match either {0} or a node previously reported as ambiguous according to net.*switch* attributes.'.format(nodename, mac)
                    if nummacs > 2:
                        errstr += ' ({0} may match a link between switches)'.format(nodename)
                log.log({'error': errstr})
                
                _nodesbymac[mac] = (None, None)
            else:
                _nodesbymac[mac] = (nodename, maccounts[ifname])
    _macsbyswitch[switch] = newmacs

def _snmp_map_switch_relay(rqid, switch, password, user):
    try:
        res = _snmp_map_switch(switch, password, user)
        payload = msgpack.packb((rqid,) + res, use_bin_type=True)
        try:
            sys.stdout.buffer.write(payload)
        except AttributeError:
            sys.stdout.write(payload)
    except exc.ConfluentException as e:
        nestedexc = e.serialize()
        payload = msgpack.packb((rqid, 1, nestedexc), use_bin_type=True)
        try:
            sys.stdout.buffer.write(payload)
        except AttributeError:
            sys.stdout.write(payload)
    except Exception as e:
        payload = msgpack.packb((rqid, 2, str(e)), use_bin_type=True)
        try:
            sys.stdout.buffer.write(payload)
        except AttributeError:
            sys.stdout.write(payload)
    finally:
        sys.stdout.flush()

def _snmp_map_switch(switch, password, user):
    haveqbridge = False
    mactobridge = {}
    conn = snmp.Session(switch, password, user)
    ifnamemap = get_portnamemap(conn)
    for vb in conn.walk('1.3.6.1.2.1.17.7.1.2.2.1.2'):
        haveqbridge = True
        oid, bridgeport = vb
        if not bridgeport:
            continue
        oid = str(oid).rsplit('.', 6)
        # if 7, then oid[1] would be vlan id
        macaddr = '{0:02x}:{1:02x}:{2:02x}:{3:02x}:{4:02x}:{5:02x}'.format(
            *([int(x) for x in oid[-6:]])
        )
        mactobridge[macaddr] = int(bridgeport)
    if not haveqbridge:
        for vb in conn.walk('1.3.6.1.2.1.17.4.3.1.2'):
            oid, bridgeport = vb
            if not bridgeport:
                continue
            oid = str(oid).rsplit('.', 6)
            macaddr = '{0:02x}:{1:02x}:{2:02x}:{3:02x}:{4:02x}:{5:02x}'.format(
                *([int(x) for x in oid[-6:]])
            )
            mactobridge[macaddr] = int(bridgeport)
    vlanstocheck = set([])
    try:
        #ciscoiftovlanmap = {}
        for vb in conn.walk('.1.3.6.1.4.1.9.9.68.1.2.2.1.2'):
            vlanstocheck.add(vb[1])
        #ciscotrunktovlanmap = {}
        for vb in conn.walk('.1.3.6.1.4.1.9.9.46.1.6.1.1.5'):
            vlanstocheck.add(vb[1])
    except Exception:
        # We might have crashed snmp on a non-cisco switch
        # in such a case, delay 8 seconds to allow recovery to complete
        eventlet.sleep(8)
    if not vlanstocheck:
        vlanstocheck.add(None)
    bridgetoifmap = {}
    for vlan in vlanstocheck:
        if vlan:
            if user:
                conn = snmp.Session(switch, password, user, 'vlan-{}'.format(vlan))
            else:
                if not isinstance(password, str):
                    password = password.decode('utf8')
                conn = snmp.Session(switch, '{}@{}'.format(password, vlan))
        for vb in conn.walk('1.3.6.1.2.1.17.1.4.1.2'):
            bridgeport, ifidx = vb
            bridgeport = int(str(bridgeport).rsplit('.', 1)[1])
            try:
                bridgetoifmap[bridgeport] = int(ifidx)
            except ValueError:
                # ifidx might be '', skip in such a case
                continue
    #OFFLOAD: end of need to offload?
    return mactobridge,ifnamemap,bridgetoifmap


switchbackoff = 30


async def find_nodeinfo_by_mac(mac, configmanager):
    now = util.monotonic_time()
    if vintage and (now - vintage) < 90 and mac in _nodesbymac:
        return _nodesbymac[mac][0], {'maccount': _nodesbymac[mac][1]}
    # do not actually sweep switches more than once every 30 seconds
    # however, if there is an update in progress, wait on it
    async for _ in update_macmap(configmanager,
                           vintage and (now - vintage) < switchbackoff):
        if mac in _nodesbymac:
            return _nodesbymac[mac][0], {'maccount': _nodesbymac[mac][1]}
    # If update_mac bailed out, still check one last time
    if mac in _nodesbymac:
        return _nodesbymac[mac][0], {'maccount': _nodesbymac[mac][1]}
    return None, {'maccount': 0}


mapupdating = asyncio.Lock()


async def update_macmap(configmanager, impatient=False):
    """Interrogate switches to build/update mac table

    Begin a rebuild process.  This process is a generator that will yield
    as each switch interrogation completes, allowing a caller to
    recheck the cache as results become possible, rather
    than having to wait for the process to complete to interrogate.
    """
    if mapupdating.locked():
        while mapupdating.locked():
            await asyncio.sleep(1)
            yield None
        return
    if impatient:
        return
    completions = _full_updatemacmap(configmanager)
    async for completion in completions:
        try:
            yield completion
        except GeneratorExit:
            # the calling function has stopped caring, but we want to finish
            # the sweep, background it
            eventlet.spawn_n(_finish_update, completions)
            raise


def _finish_update(completions):
    for _ in completions:
        pass


async def _full_updatemacmap(configmanager):
    global vintage
    global _apimacmap
    global _macmap
    global _nodesbymac
    global _switchportmap
    global _macsbyswitch
    global switchbackoff
    start = util.monotonic_time()
    async with mapupdating:
        vintage = util.monotonic_time()
        # Clear all existing entries
        _macmap = {}
        _nodesbymac = {}
        _switchportmap = {}
        if configmanager.tenant is not None:
            raise exc.ForbiddenRequest(
                'Network topology not available to tenants')
        # here's a list of switches... need to add nodes that are switches
        nodelocations = configmanager.get_node_attributes(
            configmanager.list_nodes(), ('type', 'collective.managercandidates', 'net*.switch', 'net*.switchport'))
        switches = set([])
        incollective = collective.in_collective()
        if incollective:
            mycollectivename = collective.get_myname()
        for node in nodelocations:
            cfg = nodelocations[node]
            if incollective:
                candmgrs = cfg.get('collective.managercandidates', {}).get('value', None)
                if candmgrs:
                    candmgrs = noderange.NodeRange(candmgrs, configmanager).nodes
                    if mycollectivename not in candmgrs:
                        # do not think about trying to find nodes that we aren't possibly
                        # supposed to be a manager for in a collective
                        continue
            if cfg.get('type', {}).get('value', None) == 'switch':
                switches.add(node)
            for attr in cfg:
                if not attr.endswith('.switch') or 'value' not in cfg[attr]:
                    continue
                curswitch = cfg[attr].get('value', None)
                if not curswitch:
                    continue
                switches.add(curswitch)
                switchportattr = attr + 'port'
                if switchportattr in cfg:
                    portname = cfg[switchportattr].get('value', '')
                    if not portname:
                        continue
                    if curswitch not in _switchportmap:
                        _switchportmap[curswitch] = {}
                    if (portname in _switchportmap[curswitch] and
                            _switchportmap[curswitch][portname] != node):
                        if _switchportmap[curswitch][portname] is None:
                            errstr = ('Duplicate switch attributes for {0} and '
                                      'a previously logged duplicate'.format(
                                         node))
                        else:
                            errstr = ('Duplicate switch topology config '
                                      'for {0} and {1}'.format(
                                                node,
                                            _switchportmap[curswitch][
                                                portname]))
                        log.log({'error': errstr})
                        _switchportmap[curswitch][portname] = None
                    else:
                        _switchportmap[curswitch][portname] = node
        for switch in list(_macsbyswitch):
            if switch not in switches:
                del _macsbyswitch[switch]
        switchauth = get_switchcreds(configmanager, switches)
        #pool = GreenPool(64)
        tsks = []
        for sa in switchauth:
            tsks.append(_map_switch(sa))
        for tsk in asyncio.as_completed(tsks):
            yield await tsk
    _apimacmap = _macmap
    endtime = util.monotonic_time()
    duration = endtime - start
    duration = duration * 15  # wait 15 times as long as it takes to walk
    # avoid spending a large portion of the time hitting switches with snmp
    # requests
    if duration > switchbackoff:
        switchbackoff = duration


def _dump_locations(info, macaddr, nodename=None):
    yield msg.KeyValueData({'possiblenode': nodename, 'mac': macaddr})
    retdata = {}
    portinfo = []
    for location in info:
        portinfo.append({'switch': location[0],
                         'port': location[1], 'macsonport': location[2]})
    retdata['ports'] = sorted(portinfo, key=lambda x: x['macsonport'],
                              reverse=True)
    yield msg.KeyValueData(retdata)


def handle_api_request(configmanager, inputdata, operation, pathcomponents):
    if operation == 'retrieve':
        return handle_read_api_request(pathcomponents, configmanager)
    if (operation in ('update', 'create') and
            pathcomponents == ['networking', 'macs', 'rescan']):
        if inputdata != {'rescan': 'start'}:
            raise exc.InvalidArgumentException('Input must be rescan=start')
        util.spawn(rescan(configmanager))
        return [msg.KeyValueData({'rescan': 'started'})]
    raise exc.NotImplementedException(
        'Operation {0} on {1} not implemented'.format(
            operation, '/'.join(pathcomponents)))


def get_node_fingerprints(nodename, configmanager):
    cfg = configmanager.get_node_attributes(nodename, ['net*.switch',
                                                       'net*.switchport'])
    for attrkey in cfg[nodename]:
        if attrkey.endswith('switch'):
            switch = cfg[nodename][attrkey]['value']
            port = cfg[nodename][attrkey + 'port']['value']
            yield get_fingerprint(switch, port, configmanager,
                                       _namesmatch)


def handle_read_api_request(pathcomponents, configmanager):
    # TODO(jjohnson2): discovery core.py api handler design, apply it here
    # to make this a less tangled mess as it gets extended
    if len(pathcomponents) == 1:
        return [msg.ChildCollection('macs/'),
                msg.ChildCollection('neighbors/')]
    elif pathcomponents[1] == 'neighbors':
        if len(pathcomponents) == 3 and pathcomponents[-1] == 'by-switch':
            return [msg.ChildCollection(x + '/')
                    for x in list_switches(configmanager)]
        else:
            return _handle_neighbor_query(pathcomponents[2:], configmanager)
    elif len(pathcomponents) == 2:
        if pathcomponents[-1] == 'macs':
            return [msg.ChildCollection(x) for x in (# 'by-node/',
                                                     'alldata', 'by-mac/', 'by-switch/',
                                                     'rescan')]
        elif pathcomponents[-1] == 'neighbors':
            return [msg.ChildCollection('by-switch/')]
        else:
            raise exc.NotFoundException(
                'Unknown networking resource {0}'.format(pathcomponents[-1]))
    if False and pathcomponents[2] == 'by-node':
        # TODO: should be list of node names, and then under that 'by-mac'
        if len(pathcomponents) == 3:
            return [msg.ChildCollection(x.replace(':', '-'))
                    for x in util.natural_sort(list(_nodesbymac))]
        elif len(pathcomponents) == 4:
            macaddr = pathcomponents[-1].replace('-', ':')
            return dump_macinfo(macaddr)
    elif pathcomponents[2] == 'alldata':
        return [msg.KeyValueData(_apimacmap)]
    elif pathcomponents[2] == 'by-mac':
        if len(pathcomponents) == 3:
            return [msg.ChildCollection(x.replace(':', '-'))
                    for x in sorted(list(_apimacmap))]
        elif len(pathcomponents) == 4:
            return dump_macinfo(pathcomponents[-1])
    elif pathcomponents[2] == 'by-switch':
        if len(pathcomponents) == 3:
            return [msg.ChildCollection(x + '/')
                    for x in list_switches(configmanager)]
        if len(pathcomponents) == 4:
            return [msg.ChildCollection('by-port/')]
        if len(pathcomponents) == 5:
            switchname = pathcomponents[-2]
            if switchname not in _macsbyswitch:
                raise exc.NotFoundException(
                    'No known macs for switch {0}'.format(switchname))
            return [msg.ChildCollection(x.replace('/', '-') + '/')
                    for x in util.natural_sort(list(_macsbyswitch[switchname]))]
        if len(pathcomponents) == 6:
            return [msg.ChildCollection('by-mac/')]
        if len(pathcomponents) == 7:
            switchname = pathcomponents[-4]
            portname = pathcomponents[-2]
            try:
                if portname not in _macsbyswitch[switchname]:
                    portname = portname.replace('-', '/')
                maclist = _macsbyswitch[switchname][portname]
            except KeyError:
                foundsomemacs = False
                if switchname in _macsbyswitch:
                    try:
                        matcher = re.compile(portname)
                    except Exception:
                        raise exc.InvalidArgumentException('Invalid regular expression specified')
                    maclist = []
                    for actualport in _macsbyswitch[switchname]:
                        if bool(matcher.match(actualport)):
                            foundsomemacs = True
                            maclist = maclist + _macsbyswitch[switchname][actualport]
                if not foundsomemacs:
                    raise exc.NotFoundException('No known macs for switch {0} '
                                                'port {1}'.format(switchname,
                                                                  portname))
            return [msg.ChildCollection(x.replace(':', '-'))
                    for x in sorted(maclist)]
        if len(pathcomponents) == 8:
            return dump_macinfo(pathcomponents[-1])
    elif pathcomponents[2] == 'rescan':
        return [msg.KeyValueData({'scanning': mapupdating.locked()})]
    raise exc.NotFoundException('Unrecognized path {0}'.format(
        '/'.join(pathcomponents)))


def dump_macinfo(macaddr):
    macaddr = macaddr.replace('-', ':').lower()
    info = _macmap.get(macaddr, None)
    if info is None:
        raise exc.NotFoundException(
            '{0} not found in mac table of '
            'any known switches'.format(macaddr))
    return _dump_locations(info, macaddr, _nodesbymac.get(macaddr, (None,))[0])


async def rescan(cfg):
    async for _ in update_macmap(cfg):
        pass


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '-o':
        try:
            upacker = msgpack.Unpacker(encoding='utf8')
        except TypeError:
            upacker = msgpack.Unpacker(raw=False, strict_map_key=False)
        currfl = fcntl.fcntl(sys.stdin.fileno(), fcntl.F_GETFL)
        fcntl.fcntl(sys.stdin.fileno(), fcntl.F_SETFL, currfl | os.O_NONBLOCK)

        while True:
            r = select.select([sys.stdin], [], [])
            try:
                upacker.feed(sys.stdin.buffer.read())
            except AttributeError:
                upacker.feed(sys.stdin.read())
            for cmd in upacker:
                eventlet.spawn_n(_snmp_map_switch_relay, *cmd)
        sys.exit(0)
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
