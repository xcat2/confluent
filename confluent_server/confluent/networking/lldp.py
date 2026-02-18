# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2016-2019 Lenovo
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

# Provides support for viewing and processing lldp data for switches

if __name__ == '__main__':
    import sys
    import confluent.config.configmanager as cfm
import base64
import confluent.networking.nxapi as nxapi
import confluent.networking.srlinux as srlinux
import confluent.exceptions as exc
import confluent.log as log
import confluent.messages as msg
import confluent.snmputil as snmp
import confluent.networking.netutil as netutil
import confluent.util as util
import eventlet
from eventlet.greenpool import GreenPool
import eventlet.semaphore
import re
webclient = eventlet.import_patched('pyghmi.util.webclient')
# The interesting OIDs are:
# lldpLocChassisId - to cross reference (1.0.8802.1.1.2.1.3.2.0)
# lldpLocPortId - for cross referencing.. (1.0.8802.1.1.2.1.3.7.1.3)
# 1.0.8802.1.1.2.1.3.7.1.4 - Lookup of LLDP index id to description
#                            Yet another fun fact, the LLDP port index frequent
#                            does *not* map to ifName, like a sane
#                            implementation would do.  Assume ifName equality
#                            but provide a way for 1.3.6.1.2.1.1 indicated
#                            ids to provide custom functions
#  (1.0.8802.1.1.2.1.3.7.1.2 - theoretically this process is only very useful
#                              if this is '5' meaning 'same as ifName per
#                              802.1AB-2005, however at *least* 7 has
#                              been observed to produce same results
#                              For now we'll optimistically assume
#                              equality to ifName
# 1.0.8802.1.1.2.1.4.1.1 - The information about the remote systems attached
#                            indexed by time index, local port, and an
#                            incrementing value
# 1.0.8802.1.1.2.1.4.1.1.5 - chassis id - in theory might have been useful, in
#                            practice limited as the potential to correlate
#                            to other contexts is limited.  As a result,
#                            our strategy will be to ignore this and focus
#                            instead on bridge-mib/qbridge-mib indicate data
#                            a potential exception would be pulling in things
#                            that are fundamentally network equipment,
#                            where significant ambiguity may exist.
#                            While in a 'host' scenario, there is ambiguity
#                            it is more controlled (virtual machines are given
#                            special treatment, and strategies exist for
#                            disambiguating shared management/data port, and
#                            other functions do not interact with our discovery
#                            framework
# # 1.0.8802.1.1.2.1.4.1.1.9 - SysName - could be handy hint in some scenarios
# # 1.0.8802.1.1.2.1.4.1.1.10 - SysDesc - good stuff


_neighdata = {}
_neighbypeerid = {}
_updatelocks = {}
_chassisidbyswitch = {}
_noaffluent = set([])

def lenovoname(idx, desc):
    if desc.isdigit():
        return 'Ethernet' + str(desc)
    return desc

nameoverrides = [
    (re.compile('20301\..*'), lenovoname),
]

# Lenovo chassis id rule is match only first 5 bytes for a match.....

def _api_sanitize_string(source):
    source = source.strip()
    return source.replace(':', '-').replace('/', '-')

def close_enough(fuzz, literal):
    if fuzz == literal:
        return True
    fuzz = '^' + fuzz.replace('-', '[/: -]') + '$'
    try:
        matcher = re.compile(fuzz)
    except Exception:
        raise exc.InvalidArgumentException(
            'Invalid regular expression specified')
    return bool(matcher.match(literal))


def _lldpdesc_to_ifname(switchid, idx, desc):
    for tform in nameoverrides:
        if tform[0].match(switchid):
            desc = tform[1](idx, desc)
    return desc.strip().strip('\x00')


def _dump_neighbordatum(info):
    return [msg.KeyValueData(info)]

def b64tohex(b64str):
    bd = base64.b64decode(b64str)
    bd = bytearray(bd)
    return ''.join(['{0:02x}'.format(x) for x in bd])

def get_fingerprint(switch, port, configmanager, portmatch):
    update_switch_data(switch, configmanager)
    for neigh in _neighbypeerid:
        info = _neighbypeerid[neigh]
        if neigh == '!!vintage' or info.get('switch', None) != switch:
            continue
        if 'peersha256fingerprint' not in info:
            continue
        if info.get('switch', None) != switch:
            continue
        if portmatch(info.get('portid', None), port):
            return ('sha256$' + b64tohex(info['peersha256fingerprint']),
                    info.get('verified', False))
        elif portmatch(info.get('port', None), port):
            return ('sha256$' + b64tohex(info['peersha256fingerprint']),
                    info.get('verified', False))
    return None, False


def _extract_extended_desc(info, source, integritychecked):
    source = str(source)
    info['verified']  = bool(integritychecked)
    if source.startswith('Lenovo ') and ';S2=' in source:
        desc, fprint = source.split(';S2=', 1)
        info['peerdescription'] = desc
        info['peersha256fingerprint'] = fprint
    else:
        info['peerdescription'] = source

def sanitize(val):
    # This is pretty much the same approach net-snmp takes.
    # if the string is printable as-is, then just give it as-is
    # if the string has non-printable, then hexify it
    val = str(val)
    for x in val.strip('\x00'):
        if ord(x) < 32 or ord(x) > 128:
            val = ':'.join(['{0:02x}'.format(ord(x)) for x in str(val)])
            break
    return val

def _init_lldp(data, iname, idx, idxtoportid, switch):
    if iname not in data:
        data[iname] = {'port': iname, 'portid': str(idxtoportid[idx]),
                       'chassisid': _chassisidbyswitch[switch]}

_fastbackends = {}
def detect_backend(switch, verifier):
        backend = _fastbackends.get(switch, None)
        if backend:
            return backend
        wc =  webclient.SecureHTTPConnection(
            switch, 443, verifycallback=verifier, timeout=5)
        apicheck, retcode = wc.grab_json_response_with_status('/affluent/')
        if retcode == 401 and apicheck.startswith(b'{}'):
            _fastbackends[switch] = 'affluent'
        else:
            apicheck, retcode = wc.grab_json_response_with_status('/api/')
            if retcode == 400 and apicheck.startswith(b'{"imdata":['):
                _fastbackends[switch] = 'nxapi'
            else:
                rsp = wc.grab_json_response_with_status('/jsonrpc', {'dummy': 'data'}, returnheaders=True)
                if rsp[1] == 401 and rsp[2].get('WWW-Authenticate', '').startswith('Basic realm="SRLinux"'):
                    _fastbackends[switch] = 'srlinux'
        return _fastbackends.get(switch, None)

def _extract_neighbor_data_https(switch, user, password, cfm, lldpdata):
    kv = util.TLSCertVerifier(cfm, switch,
                                  'pubkeys.tls_hardwaremanager').verify_cert
    backend = detect_backend(switch, kv)
    if not backend:
        raise Exception("No HTTPS backend identified")
    wc =  webclient.SecureHTTPConnection(
                switch, 443, verifycallback=kv, timeout=5)
    if backend == 'affluent':
        return _extract_neighbor_data_affluent(switch, user, password, cfm, lldpdata, wc)
    elif backend == 'nxapi':
        return _extract_neighbor_data_nxapi(switch, user, password, cfm, lldpdata, wc)
    elif backend == 'srlinux':
        return _extract_neighbor_data_srlinux(switch, user, password, cfm, lldpdata, wc)



def _extract_neighbor_data_nxapi(switch, user, password, cfm, lldpdata, wc):
    cli = nxapi.NxApiClient(switch, user, password, cfm)
    lldpinfo = cli.get_lldp()
    for port in lldpinfo:
        portdata = lldpinfo[port]
        peerid = '{0}.{1}'.format(
            portdata.get('peerchassisid', '').replace(':', '-').replace('/', '-'),
            portdata.get('peerportid', '').replace(':', '-').replace('/', '-'),
        )
        portdata['peerid'] = peerid
        _extract_extended_desc(portdata, portdata['peerdescription'], True)
        portdata['switch'] = switch
        _neighbypeerid[peerid] = portdata
        lldpdata[port] = portdata
    _neighdata[switch] = lldpdata

def _extract_neighbor_data_srlinux(switch, user, password, cfm, lldpdata, wc):
    cli = srlinux.SRLinuxClient(switch, user, password, cfm)
    lldpinfo = cli.get_lldp()
    for port in lldpinfo:
        portdata = lldpinfo[port]
        peerid = '{0}.{1}'.format(
            portdata.get('peerchassisid', '').replace(':', '-').replace('/', '-'),
            portdata.get('peerportid', '').replace(':', '-').replace('/', '-'),
        )
        portdata['peerid'] = peerid
        _extract_extended_desc(portdata, portdata['peerdescription'], True)
        portdata['switch'] = switch
        _neighbypeerid[peerid] = portdata
        lldpdata[port] = portdata
    _neighdata[switch] = lldpdata


def _extract_neighbor_data_affluent(switch, user, password, cfm, lldpdata, wc):
    wc.set_basic_credentials(user, password)
    neighdata = wc.grab_json_response('/affluent/lldp/all')
    chassisid = neighdata['chassis']['id']
    _chassisidbyswitch[switch] = chassisid,
    for record in neighdata['neighbors']:
        localport = record['localport']
        peerid = '{0}.{1}'.format(
            record.get('peerchassisid', '').replace(':', '-').replace('/', '-'),
            record.get('peerportid', '').replace(':', '-').replace('/', '-'),
        )
        portdata = {
            'verified': True,  # It is over TLS after all
            'peerdescription': record.get('peerdescription', None),
            'peerchassisid': record['peerchassisid'],
            'peername': record['peername'],
            'switch': switch,
            'chassisid': chassisid,
            'portid': record['localport'],
            'peerportid': record['peerportid'],
            'port': record['localport'],
            'peerid': peerid,
        }
        _extract_extended_desc(portdata, portdata['peerdescription'], True)
        _neighbypeerid[peerid] = portdata
        lldpdata[localport] = portdata
    _neighdata[switch] = lldpdata


def _extract_neighbor_data_b(args):
    """Build LLDP data about elements connected to switch

    args are carried as a tuple, because of eventlet convenience
    """
    # Safely unpack args with defaults to avoid IndexError
    switch = args[0] if len(args) > 0 else None
    password = args[1] if len(args) > 1 else None
    user = args[2] if len(args) > 2 else None
    cfm = args[3] if len(args) > 3 else None
    privproto = args[4] if len(args) > 4 else None
    force = args[5] if len(args) > 5 else False
    vintage = _neighdata.get(switch, {}).get('!!vintage', 0)
    now = util.monotonic_time()
    if vintage > (now - 60) and not force:
        return
    lldpdata = {'!!vintage': now}
    try:
        return _extract_neighbor_data_https(switch, user, password, cfm, lldpdata)
    except Exception as e:
        pass
    conn = snmp.Session(switch, password, user, privacy_protocol=privproto)
    sid = None
    for sysid in conn.walk('1.3.6.1.2.1.1.2'):
        sid = str(sysid[1][6:])
    _noaffluent.add(switch)
    idxtoifname = {}
    idxtoportid = {}
    _chassisidbyswitch[switch] = sanitize(list(
        conn.walk('1.0.8802.1.1.2.1.3.2'))[0][1])
    for oidindex in conn.walk('1.0.8802.1.1.2.1.3.7.1.3'):
        idx = oidindex[0][-1]
        idxtoportid[idx] = sanitize(oidindex[1])
    for oidindex in conn.walk('1.0.8802.1.1.2.1.3.7.1.4'):
        idx = oidindex[0][-1]
        idxtoifname[idx] = _lldpdesc_to_ifname(sid, idx, str(oidindex[1]))
    for remotedesc in conn.walk('1.0.8802.1.1.2.1.4.1.1.10'):
        iname = idxtoifname.get(remotedesc[0][-2],
                                idxtoportid.get(remotedesc[0][-2], None))
        if iname is None:
            continue
        _init_lldp(lldpdata, iname, remotedesc[0][-2], idxtoportid, switch)
        _extract_extended_desc(lldpdata[iname], remotedesc[1], user)
    for remotename in conn.walk('1.0.8802.1.1.2.1.4.1.1.9'):
        iname = idxtoifname.get(remotename[0][-2],
                                idxtoportid.get(remotename[0][-2], None))
        if iname is None:
            continue
        _init_lldp(lldpdata, iname, remotename[0][-2], idxtoportid, switch)
        lldpdata[iname]['peername'] = str(remotename[1])
    for remotename in conn.walk('1.0.8802.1.1.2.1.4.1.1.7'):
        iname = idxtoifname.get(remotename[0][-2],
                                idxtoportid.get(remotename[0][-2], None))
        if iname is None:
            continue
        _init_lldp(lldpdata, iname, remotename[0][-2], idxtoportid, switch)
        lldpdata[iname]['peerportid'] = sanitize(remotename[1])
    for remoteid in conn.walk('1.0.8802.1.1.2.1.4.1.1.5'):
        iname = idxtoifname.get(remoteid[0][-2],
                                idxtoportid.get(remoteid[0][-2], None))
        if iname is None:
            continue
        _init_lldp(lldpdata, iname, remoteid[0][-2], idxtoportid, switch)
        lldpdata[iname]['peerchassisid'] = sanitize(remoteid[1])
    for entry in lldpdata:
        if entry == '!!vintage':
            continue
        entry = lldpdata[entry]
        entry['switch'] = switch
        peerid = '{0}.{1}'.format(
            entry.get('peerchassisid', '').replace(':', '-').replace('/', '-'),
            entry.get('peerportid', '').replace(':', '-').replace('/', '-'))
        entry['peerid'] = peerid
        _neighbypeerid[peerid] = entry
    _neighdata[switch] = lldpdata


def update_switch_data(switch, configmanager, force=False, retexc=False):
    switchcreds = netutil.get_switchcreds(configmanager, (switch,))[0]
    ndr = _extract_neighbor_data(switchcreds + (force, retexc))
    if retexc and isinstance(ndr, Exception):
        raise ndr
    return _neighdata.get(switch, {})


def update_neighbors(configmanager, force=False, retexc=False):
    return _update_neighbors_backend(configmanager, force, retexc)


def _update_neighbors_backend(configmanager, force, retexc):
    global _neighdata
    global _neighbypeerid
    vintage = _neighdata.get('!!vintage', 0)
    now = util.monotonic_time()
    if vintage > (now - 60) and not force:
        return
    _neighdata = {'!!vintage': now}
    _neighbypeerid = {'!!vintage': now}
    switches = netutil.list_switches(configmanager)
    switchcreds = netutil.get_switchcreds(configmanager, switches)
    switchcreds = [ x + (force, retexc) for x in switchcreds]
    pool = GreenPool(64)
    for ans in pool.imap(_extract_neighbor_data, switchcreds):
        yield ans


def _extract_neighbor_data(args):
    # single switch neighbor data update
    switch = args[0]
    if switch not in _updatelocks:
        _updatelocks[switch] = eventlet.semaphore.Semaphore()
    if _updatelocks[switch].locked():
        while _updatelocks[switch].locked():
            eventlet.sleep(1)
        return
    try:
        with _updatelocks[switch]:
            return _extract_neighbor_data_b(args)
    except Exception as e:
        yieldexc = False
        if len(args) >= 7:
            yieldexc = args[6]
        if yieldexc:
            return e
        else:
            log.logtrace()

if __name__ == '__main__':
    # a quick one-shot test, args are switch and snmpv1 string for now
    # (should do three argument form for snmpv3 test
    import sys
    _extract_neighbor_data((sys.argv[1], sys.argv[2], None, True))
    print(repr(_neighdata))


multi_selectors = set(['by-switch', 'by-peername', 'by-peerportid',
                        'by-peerchassisid', 'by-chassisid', 'by-port',
                        'by-portid'])
single_selectors = set(['by-peerid'])

def _parameterize_path(pathcomponents):
    listrequested = False
    childcoll = True
    if len(pathcomponents) % 2 == 1:
        listrequested = pathcomponents[-1]
        pathcomponents = pathcomponents[:-1]
    pathit = iter(pathcomponents)
    keyparams = {}
    validselectors = multi_selectors | single_selectors
    for key, val in zip(pathit, pathit):
        if key not in validselectors:
            raise exc.NotFoundException('{0} is not valid here'.format(key))
        keyparams[key] = val
        validselectors.discard(key)
        if key == 'by-switch':
            validselectors.add('by-port')
        if key in single_selectors:
            childcoll = False
            validselectors = set([])
    return validselectors, keyparams, listrequested, childcoll

def list_info(parms, requestedparameter):
    #{u'by-switch': u'r8e1', u'by-port': u'e'}
    #by-peerport
    suffix = '/' if requestedparameter in multi_selectors else ''
    results = set([])
    requestedparameter = requestedparameter.replace('by-', '')
    for info in _neighbypeerid:
        if info == '!!vintage':
            continue
        info = _neighbypeerid[info]
        for mk in parms:
            mk = mk.replace('by-', '')
            if mk not in info:
                continue
            if (not close_enough(parms['by-' + mk], info[mk]) or
                    requestedparameter not in info):
                break
        else:
            candidate = info[requestedparameter]
            if candidate:
                candidate = candidate.strip()
                if candidate != '':
                    results.add(_api_sanitize_string(candidate))
    return [msg.ChildCollection(x + suffix) for x in util.natural_sort(results)]

def _handle_neighbor_query(pathcomponents, configmanager):
    choices, parms, listrequested, childcoll = _parameterize_path(
        pathcomponents)
    if not childcoll:  # this means it's a single entry with by-peerid
        # guaranteed
        if (parms['by-peerid'] not in _neighbypeerid and
                _neighbypeerid.get('!!vintage', 0) < util.monotonic_time() - 60):
            for x in update_neighbors(configmanager, retexc=True):
                if isinstance(x, Exception):
                    raise x
        if parms['by-peerid'] not in _neighbypeerid:
            raise exc.NotFoundException('No matching peer known')
        return _dump_neighbordatum(_neighbypeerid[parms['by-peerid']])
    if not listrequested:  # the query is for currently valid choices
        return [msg.ChildCollection(x + '/') for x in sorted(list(choices))]
    if listrequested not in multi_selectors | single_selectors:
        raise exc.NotFoundException('{0} is not found'.format(listrequested))
    if 'by-switch' in parms:
        update_switch_data(parms['by-switch'], configmanager, retexc=True)
    else:
        for x in update_neighbors(configmanager, retexc=True):
            if isinstance(x, Exception):
                raise x
    return list_info(parms, listrequested)

