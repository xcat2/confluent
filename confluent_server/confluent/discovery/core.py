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

# This manages the detection and auto-configuration of nodes.
# Discovery sources may implement scans and may be passive or may provide
# both.

# The phases and actions:
# - Detect - Notice the existance of a potentially supported target
#        - Potentially apply a secure replacement for default credential
#           (perhaps using some key identifier combined with some string
#            denoting temporary use, and use confluent master integrity key
#            to generate a password in a formulaic way?)
#       - Do some universal reconfiguration if applicable (e.g. if something is
#         part of an enclosure with an optionally enabled enclosure manager,
#         check and request enclosure manager enablement
#       - Throughout all of this, at this phase no sensitive data is divulged,
#         only using credentials that are factory default or equivalent to
#         factory default
#       - Request transition to Locate
# - Locate - Use available cues to ascertain the physical location.  This may
#         be mac address lookup through switch or correlated by a server
#         enclosure manager.  If the location data suggests a node identity,
#         then proceed to the 'verify' state
# - Verify - Given the current information and candidate upstream verifier,
#            verify the authenticity of the servers claim in an automated way
#            if possible.  A few things may happen at this juncture
#               - Verification outright fails (confirmed negative response)
#                    - Audit log entry created, element is not *allowed* to
#                      proceed
#               - Verification not possible (neither good or bad)
#                   - If security policy is set to low, proceed to 'Manage'
#                   - Otherwise, log the detection event and stop (user
#                     would then manually bless the endpoint if applicable
#               - Verification succeeds
#                   - If security policy is set to strict (or manual, whichever
#                     word works best, note the successfull verification, but
#                     do not manage
#                   - Otherwise, proceed to 'Manage'
#  -Pre-configure - Given data up to this point, try to do some pre-config.
#                   For example, if located and X, then check for S, enable S
#                   This happens regardless of verify, as verify may depend on
#                   S
#  - Manage
#     - Create the node if autonode (Deferred)
#     - If there is not a defined ip address, collect the current LLA and use
#       that value.
#     - If no username/password defined, generate a unique password, 20 bytes
#       long, written to pass most complexity rules (15 random bytes, base64,
#       retry until uppercase, lowercase, digit, and symbol all present)
#     - Apply defined configuration to endpoint

import asyncio
import base64
import confluent.config.configmanager as cfm
import confluent.collective.manager as collective
import confluent.discovery.protocols.pxe as pxe
import confluent.discovery.protocols.ssdp as ssdp
#import confluent.discovery.protocols.mdns as mdns
import confluent.discovery.protocols.slp as slp
import confluent.discovery.handlers.imm as imm
import confluent.discovery.handlers.cpstorage as cpstorage
import confluent.discovery.handlers.tsm as tsm
import confluent.discovery.handlers.pxe as pxeh
import confluent.discovery.handlers.smm as smm
import confluent.discovery.handlers.xcc as xcc
import confluent.discovery.handlers.xcc3 as xcc3
import confluent.discovery.handlers.smm3 as smm3
import confluent.discovery.handlers.megarac as megarac
import confluent.exceptions as exc
import confluent.log as log
import confluent.messages as msg
import confluent.networking.macmap as macmap
import confluent.noderange as noderange
import confluent.tasks as tasks
import confluent.util as util
import inspect
import json
import traceback
import shlex
import struct
import socket
import socket as nsocket


autosensors = set()
scanner = None

try:
    unicode
except NameError:
    unicode = str

try:
    import cryptography.x509.verification as verification
except ImportError:
    verification = None

class nesteddict(dict):

    def __missing__(self, key):
        v = self[key] = nesteddict()
        return v

nodehandlers = {
    'service:lenovo-smm': smm,
    'service:lenovo-smm2': smm,
    'lenovo-smm3': smm3,
    'lenovo-xcc': xcc,
    'lenovo-xcc3': xcc3,
    'megarac-bmc': megarac,
    'service:management-hardware.IBM:integrated-management-module2': imm,
    'pxe-client': pxeh,
    'onie-switch': None,
    'cumulus-switch': None,
    'affluent-switch': None,
    #'openbmc': None,
    'service:io-device.Lenovo:management-module': None,
    'service:thinkagile-storage': cpstorage,
    'service:lenovo-tsm': tsm,
}

servicenames = {
    'pxe-client': 'pxe-client',
    'onie-switch': 'onie-switch',
    'cumulus-switch': 'cumulus-switch',
    'service:lenovo-smm': 'lenovo-smm',
    'service:lenovo-smm2': 'lenovo-smm2',
    'lenovo-smm3': 'lenovo-smm3',
    'affluent-switch': 'affluent-switch',
    'lenovo-xcc': 'lenovo-xcc',
    'lenovo-xcc3': 'lenovo-xcc3',
    'megarac-bmc': 'megarac-bmc',
    #'openbmc': 'openbmc',
    'service:management-hardware.IBM:integrated-management-module2': 'lenovo-imm2',
    'service:io-device.Lenovo:management-module': 'lenovo-switch',
    'service:thinkagile-storage': 'thinkagile-storagebmc',
    'service:lenovo-tsm': 'lenovo-tsm',
}

servicebyname = {
    'pxe-client': 'pxe-client',
    'onie-switch': 'onie-switch',
    'cumulus-switch': 'cumulus-switch',
    'lenovo-smm': 'service:lenovo-smm',
    'lenovo-smm2': 'service:lenovo-smm2',
    'lenovo-smm3': 'lenovo-smm3',
    'affluent-switch': 'affluent-switch',
    'lenovo-xcc': 'lenovo-xcc',
    'lenovo-xcc3': 'lenovo-xcc3',
    'megarac-bmc': 'megarac-bmc',
    'lenovo-imm2': 'service:management-hardware.IBM:integrated-management-module2',
    'lenovo-switch': 'service:io-device.Lenovo:management-module',
    'thinkagile-storage': 'service:thinkagile-storagebmc',
    'lenovo-tsm': 'service:lenovo-tsm',
}

runningevals = {}
# Passive-only auto-detection protocols:
# PXE

# Both passive and active
# SLP (passive mode listens for SLP DA and unicast interrogation of the system)
# mDNS
# SSD

# Also there are location providers
# Switch
# chassis
# chassis may in turn describe more chassis

# We normalize discovered node data to the following pieces of information:
# * Detected node name (if available, from switch discovery or similar or
#   auto generated node name.
# * Model number
# * Model name
# * Serial number
# * System UUID (in x86 space, specifically whichever UUID would be in DMI)
# * Network interfaces and addresses
# * Switch connectivity information
# * enclosure information
# * Management TLS fingerprint if validated (switch publication or enclosure)
# * System TLS fingerprint if validated (switch publication or system manager)


#TODO: by serial, by uuid, by node
known_info = {}
known_services = {}
known_serials = {}
known_uuids = nesteddict()
known_nodes = nesteddict()
unknown_info = {}
pending_nodes = {}
pending_by_uuid = {}


def register_affluent(affluenthdl):
    global affluent
    affluent = affluenthdl

def enrich_pxe_info(info):
    sn = None
    mn = None
    nodename = info.get('nodename', None)
    uuid = info.get('uuid', '')
    if not uuid_is_valid(uuid):
        return info
    for mac in known_uuids.get(uuid, {}):
        if not sn and 'serialnumber' in known_uuids[uuid][mac]:
            info['serialnumber'] = known_uuids[uuid][mac]['serialnumber']
        if not mn and 'modelnumber' in known_uuids[uuid][mac]:
            info['modelnumber'] = known_uuids[uuid][mac]['modelnumber']
        if nodename is None and 'nodename' in known_uuids[uuid][mac]:
            info['nodename'] = known_uuids[uuid][mac]['nodename']



def uuid_is_valid(uuid):
    if not uuid:
        return False
    return uuid.lower() not in ('00000000-0000-0000-0000-000000000000',
                                'ffffffff-ffff-ffff-ffff-ffffffffffff',
                                '00112233-4455-6677-8899-aabbccddeeff',
                                '03000200-0400-0500-0006-000700080009',
                                '20202020-2020-2020-2020-202020202020')

def _printable_ip(sa):
    return nsocket.getnameinfo(
        sa, nsocket.NI_NUMERICHOST|nsocket.NI_NUMERICSERV)[0]

def send_discovery_datum(info):
    addresses = info.get('addresses', [])
    addresses = util.natural_sort(addresses)
    if info['handler'] == pxeh:
        enrich_pxe_info(info)
    yield msg.KeyValueData({'nodename': info.get('nodename', '')})
    if not info.get('forwarder_server', None):
        yield msg.KeyValueData({'ipaddrs': [_printable_ip(x) for x in addresses]})
    switch = info.get('forwarder_server', None)
    if switch:
        yield msg.KeyValueData({'switch': switch})
        yield msg.KeyValueData({'switchport': info['port']})
    sn = info.get('serialnumber', '')
    mn = info.get('modelnumber', '')
    uuid = info.get('uuid', '')
    if uuid:
        relatedmacs = []
        for mac in known_uuids.get(uuid, {}):
            if mac and mac != info.get('hwaddr', ''):
                relatedmacs.append(mac)
        if relatedmacs:
            yield msg.KeyValueData({'relatedmacs': relatedmacs})
    yield msg.KeyValueData({'serialnumber': sn})
    yield msg.KeyValueData({'modelnumber': mn})
    yield msg.KeyValueData({'uuid': uuid})
    if 'enclosure.uuid' in info:
        yield msg.KeyValueData({'enclosure_uuid': info['enclosure.uuid']})
    if 'enclosure.bay' in info:
        yield msg.KeyValueData({'bay': int(info['enclosure.bay'])})
    yield msg.KeyValueData({'macs': [info.get('hwaddr', '')]})
    types = []
    for infotype in info.get('services', []):
        if infotype in servicenames:
            types.append(servicenames[infotype])
    yield msg.KeyValueData({'types': types})
    if 'otheraddresses' in info:
        yield msg.KeyValueData({'otheripaddrs': list(info['otheraddresses'])})
    if 'location' in info:
        yield msg.KeyValueData({'location': info['location']})
    if 'room' in info:
        yield msg.KeyValueData({'room': info['room']})
    if 'rack' in info:
        yield msg.KeyValueData({'rack': info['rack']})
    if 'u' in info:
        yield msg.KeyValueData({'lowest_u': info['u']})
    if 'hostname' in info:
        yield msg.KeyValueData({'hostname': info['hostname']})
    if 'modelname' in info:
        yield msg.KeyValueData({'modelname': info['modelname']})


def _info_matches(info, criteria):
    model = criteria.get('by-model', None)
    devtype = criteria.get('by-type', None)
    node = criteria.get('by-node', None)
    serial = criteria.get('by-serial', None)
    status = criteria.get('by-state', None)
    uuid = criteria.get('by-uuid', None)
    if model and info.get('modelnumber', None) != model:
        return False
    if devtype and devtype not in info.get('services', []):
            return False
    if node and info.get('nodename', None) != node:
        return False
    if serial and info.get('serialnumber', None) != serial:
        return False
    if status and info.get('discostatus', None) != status:
        return False
    if uuid and info.get('uuid', None) != uuid:
        return False
    return True


def list_matching_nodes(criteria):
    retnodes = []
    for node in known_nodes:
        for mac in known_nodes[node]:
            if mac not in known_info:
                continue
            info = known_info[mac]
            if _info_matches(info, criteria):
                retnodes.append(node)
                break
    retnodes.sort(key=noderange.humanify_nodename)
    return [msg.ChildCollection(node + '/') for node in retnodes]


def list_matching_serials(criteria):
    for serial in sorted(list(known_serials)):
        info = known_serials[serial]
        if _info_matches(info, criteria):
            yield msg.ChildCollection(serial + '/')

def list_matching_uuids(criteria):
    for uuid in sorted(list(known_uuids)):
        for mac in known_uuids[uuid]:
            info = known_uuids[uuid][mac]
            if _info_matches(info, criteria):
                yield msg.ChildCollection(uuid + '/')
                break


def list_matching_states(criteria):
    return [msg.ChildCollection(x) for x in ('discovered/', 'identified/',
                                             'unidentified/')]

def list_matching_macs(criteria):
    for mac in sorted(list(known_info)):
        info = known_info[mac]
        if _info_matches(info, criteria):
            yield msg.ChildCollection(mac.replace(':', '-'))


def list_matching_types(criteria):
    rettypes = []
    for infotype in known_services:
        typename = servicenames[infotype]
        if ('by-model' not in criteria or
                criteria['by-model'] in known_services[infotype]):
            rettypes.append(typename)
    return [msg.ChildCollection(typename + '/')
            for typename in sorted(rettypes)]


def list_matching_models(criteria):
    for model in sorted(list(detected_models())):
        if ('by-type' not in criteria or
                model in known_services[criteria['by-type']]):
            yield msg.ChildCollection(model + '/')


def show_info(mac):
    mac = mac.replace('-', ':')
    if mac not in known_info:
        raise exc.NotFoundException(mac + ' not a known mac address')
    for i in send_discovery_datum(known_info[mac]):
        yield i

def dump_discovery():
    infobymac = {}
    for mac in known_info:
        infobymac[mac] = {}
        for i in send_discovery_datum(known_info[mac]):
            for kn in i.kvpairs:
                infobymac[mac][kn] = i.kvpairs[kn]
    yield msg.KeyValueData(infobymac)

list_info = {
    'by-node': list_matching_nodes,
    'by-serial': list_matching_serials,
    'by-type': list_matching_types,
    'by-model': list_matching_models,
    'by-mac': list_matching_macs,
    'by-state': list_matching_states,
    'by-uuid': list_matching_uuids,
}

multi_selectors = set([
    'by-type',
    'by-model',
    'by-state',
    'by-uuid',
])


node_selectors = set([
    'by-node',
    'by-serial',
])


single_selectors = set([
    'by-mac',
])


def addr_to_number(addr):
    addr = socket.inet_pton(socket.AF_INET, addr)
    num = struct.unpack('!I', addr)[0]
    return num

def number_to_addr(number):
    addr = struct.pack('!I', number)
    addr = socket.inet_ntop(socket.AF_INET, addr)
    return addr

def iterate_addrs(addrs, countonly=False):
    if '.' not in addrs:
        raise exc.InvalidArgumentException('IPv4 only supported')
    if '-' in addrs:
        first, last = addrs.split('-', 1)
        currn = addr_to_number(first)
        last = addr_to_number(last)
        if last < currn:
            tm = currn
            currn = last
            currn = tm
        if (last - currn) > 65538:
            raise exc.InvalidArgumentException("Too many ip addresses")
        if countonly:
            yield last - currn + 1
            return
        while currn <= last:
            yield number_to_addr(currn)
            currn += 1
    elif '/' in addrs:
        first, plen = addrs.split('/', 1)
        plen = int(plen)
        if plen > 32:
            raise exc.InvalidArgumentException("Invalid prefix length")
        mask = (2**32 - 1) ^ (2**(32 - plen) - 1)
        currn = addr_to_number(first)
        currn = currn & mask
        numips = 2**(32 - plen)
        if numips > 65538:
            raise exc.InvalidArgumentException("Too many ip addresses")
        if countonly:
            yield numips
            return
        while numips > 0:
            yield number_to_addr(currn)
            currn += 1
            numips -= 1
    else:
        if countonly:
            yield 1
            return
        yield addrs

def _parameterize_path(pathcomponents):
    listrequested = False
    childcoll = True
    if len(pathcomponents) % 2 == 1:
        listrequested = pathcomponents[-1]
        pathcomponents = pathcomponents[:-1]
    pathit = iter(pathcomponents)
    keyparams = {}
    validselectors = multi_selectors | node_selectors | single_selectors
    for key, val in zip(pathit, pathit):
        if key not in validselectors:
            raise exc.NotFoundException('{0} is not valid here'.format(key))
        if key == 'by-type':
            keyparams[key] = servicebyname.get(val, '!!!!invalid-type')
        else:
            keyparams[key] = val
        validselectors.discard(key)
        if key in single_selectors:
            childcoll = False
            validselectors = set([])
        elif key in node_selectors:
            validselectors = single_selectors | set([])
    return validselectors, keyparams, listrequested, childcoll


def handle_autosense_config(operation, inputdata):
    autosense = cfm.get_global('discovery.autosense')
    autosense = autosense or autosense is None
    if operation == 'retrieve':
        yield msg.KeyValueData({'enabled': autosense})
    elif operation == 'update':
        enabled = inputdata['enabled']
        if type(enabled) in (unicode, bytes):
            enabled = enabled.lower() in ('true', '1', 'y', 'yes', 'enable',
                                          'enabled')
        if autosense == enabled:
            return
        cfm.set_global('discovery.autosense', enabled)
        if enabled:
            start_autosense()
        else:
            stop_autosense()

def get_subscriptions():
    try:
        with open('/etc/confluent/discovery_subscriptions.json', 'r') as ds:
            dst = ds.read()
            if dst:
                return json.loads(dst)
    except Exception:
        pass
    return {}

def save_subscriptions(subs):
    with open('/etc/confluent/discovery_subscriptions.json', 'w') as dso:
        dso.write(json.dumps(subs))


async def register_remote_addrs(addresses, configmanager):
    async def register_remote_addr(addr):
        nd = {
            'addresses': [(addr, 443)]
        }
        try:
            sd = await ssdp.check_fish(('/DeviceDescription.json', nd))
            if not sd:
                return addr, False
            if 'macaddress' in sd['attributes']:
                sd['hwaddr'] = sd['attributes']['macaddress']
            else:
                sd['hwaddr'] = sd['attributes']['mac-address']
            if 'lenovo-xcc3' in sd['services']:
                nh = xcc3.NodeHandler(sd, configmanager)
            elif 'lenovo-xcc' in sd['services']:
                nh = xcc.NodeHandler(sd, configmanager)
            await nh.scan()
            await detected(nh.info)
        except Exception:
            return addr, False
        return addr, True
    #rpool = eventlet.greenpool.GreenPool(512)
    for count in iterate_addrs(addresses, True):
        yield msg.ConfluentResourceCount(count)
    return  # ASYNC
    for result in rpool.imap(register_remote_addr, iterate_addrs(addresses)):
        if result[1]:
            yield msg.CreatedResource(result[0])
        else:
            yield msg.ConfluentResourceNotFound(result[0])


async def handle_api_request(configmanager, inputdata, operation, pathcomponents):
    if pathcomponents == ['discovery', 'autosense']:
        return handle_autosense_config(operation, inputdata)
    if operation == 'retrieve' and pathcomponents[:2] == ['discovery', 'subscriptions']:
        if len(pathcomponents) > 2:
            raise Exception('TODO')
        currsubs = get_subscriptions()
        return [msg.ChildCollection(x) for x in currsubs]
    elif operation == 'retrieve':
        return handle_read_api_request(pathcomponents)
    elif (operation in ('update', 'create') and
            pathcomponents == ['discovery', 'rescan']):
        if inputdata != {'rescan': 'start'}:
            raise exc.InvalidArgumentException()
        await rescan()
        return (msg.KeyValueData({'rescan': 'started'}),)
    elif operation in ('update', 'create') and pathcomponents[:2] == ['discovery', 'subscriptions']:
        target = pathcomponents[2]
        affluent.subscribe_discovery(target, configmanager, collective.get_myname())
        currsubs = get_subscriptions()
        currsubs[target] = {}
        save_subscriptions(currsubs)
        return (msg.KeyValueData({'status': 'subscribed'}),)
    elif operation == 'delete' and pathcomponents[:2] == ['discovery', 'subscriptions']:
        target = pathcomponents[2]
        affluent.unsubscribe_discovery(target, configmanager, collective.get_myname())
        currsubs = get_subscriptions()
        if target in currsubs:
            del currsubs[target]
            save_subscriptions(currsubs)
        return (msg.KeyValueData({'status': 'unsubscribed'}),)
    elif operation in ('update', 'create'):
        if pathcomponents == ['discovery', 'register']:
            if 'addresses' not in inputdata:
                raise exc.InvalidArgumentException('Missing address in input')
            return await register_remote_addrs(inputdata['addresses'], configmanager)
        if 'node' not in inputdata:
            raise exc.InvalidArgumentException('Missing node name in input')
        mac = _get_mac_from_query(pathcomponents)
        info = known_info[mac]
        if info['handler'] is None:
            raise exc.NotImplementedException(
                'Unable to {0} to {1}'.format(operation,
                                              '/'.join(pathcomponents)))
        handler = info['handler'].NodeHandler(info, configmanager)
        try:
            await eval_node(configmanager, handler, info, inputdata['node'],
                      manual=True)
        except Exception as e:
            # or... incorrect passworod provided..
            if 'Incorrect password' in str(e) or 'Unauthorized name' in str(e):
                return [msg.ConfluentTargetInvalidCredentials(
                    inputdata['node'])]
            raise
        return [msg.AssignedResource(inputdata['node'])]
    elif operation == 'delete':
        mac = _get_mac_from_query(pathcomponents)
        for node in known_nodes:
            if mac in known_nodes[node]:
                del known_nodes[node][mac]
        if mac in known_info:
            del known_info[mac]
        return [msg.DeletedResource(mac)]
    raise exc.NotImplementedException(
        'Unable to {0} to {1}'.format(operation, '/'.join(pathcomponents)))


def _get_mac_from_query(pathcomponents):
    _, queryparms, _, _ = _parameterize_path(pathcomponents[1:])
    if 'by-mac' not in queryparms:
        raise exc.InvalidArgumentException('Must target using "by-mac"')
    mac = queryparms['by-mac'].replace('-', ':')
    if mac not in known_info:
        raise exc.NotFoundException('{0} not found'.format(mac))
    return mac


def handle_read_api_request(pathcomponents):
    # TODO(jjohnson2): This should be more generalized...
    #  odd indexes into components are 'by-'*, even indexes
    # starting at 2 are parameters to previous index
    if pathcomponents == ['discovery', 'rescan']:
        return (msg.KeyValueData({'scanning': bool(scanner)}),)
    if pathcomponents == ['discovery', 'alldata']:
        return dump_discovery()
    subcats, queryparms, indexof, coll = _parameterize_path(pathcomponents[1:])
    if len(pathcomponents) == 1:
        dirlist = [msg.ChildCollection(x + '/') for x in sorted(list(subcats))]
        dirlist.append(msg.ChildCollection('rescan'))
        dirlist.append(msg.ChildCollection('autosense'))
        dirlist.append(msg.ChildCollection('alldata'))
        dirlist.append(msg.ChildCollection('subscriptions/'))
        return dirlist
    if not coll:
        return show_info(queryparms['by-mac'])
    if not indexof:
        return [msg.ChildCollection(x + '/') for x in sorted(list(subcats))]
    if indexof not in list_info:
        raise exc.NotFoundException('{0} is not found'.format(indexof))
    return list_info[indexof](queryparms)


def detected_services():
    for srv in known_services:
        yield servicenames[srv]


def detected_models():
    knownmodels = set([])
    for info in known_info:
        info = known_info[info]
        if 'modelnumber' in info and info['modelnumber'] not in knownmodels:
            knownmodels.add(info['modelnumber'])
            yield info['modelnumber']


async def _recheck_nodes(nodeattribs, configmanager):
    if not cfm.config_is_ready():
        return
    if rechecklock.locked():
        # if already in progress, don't run again
        # it may make sense to schedule a repeat, but will try the easier and less redundant way first
        return
    async with rechecklock:
        return await _recheck_nodes_backend(nodeattribs, configmanager)

async def _recheck_nodes_backend(nodeattribs, configmanager):
    global rechecker
    _map_unique_ids(nodeattribs)
    # for the nodes whose attributes have changed, consider them as potential
    # strangers
    if nodeattribs:
        macmap.vintage = 0  # expire current mac map data, in case
        # the attributes changed impacted the result
    for node in nodeattribs:
        if node in known_nodes:
            for somemac in known_nodes[node]:
                unknown_info[somemac] = known_nodes[node][somemac]
                unknown_info[somemac]['discostatus'] = 'unidentified'
    # Now we go through ones we did not find earlier
    for mac in list(unknown_info):
        try:
            await _recheck_single_unknown(configmanager, mac)
        except Exception:
            traceback.print_exc()
            continue
    # now we go through ones that were identified, but could not pass
    # policy or hadn't been able to verify key
    for nodename in pending_nodes:
        info = pending_nodes[nodename]
        try:
            if info['handler'] is None:
                next
            handler = info['handler'].NodeHandler(info, configmanager)
            tasks.spawn(eval_node(configmanager, handler, info, nodename))
        except Exception:
            traceback.print_exc()
            log.log({'error': 'Unexpected error during discovery of {0}, check debug '
                              'logs'.format(nodename)})


async def _recheck_single_unknown(configmanager, mac):
    info = unknown_info.get(mac, None)
    await _recheck_single_unknown_info(configmanager, info)


async def _recheck_single_unknown_info(configmanager, info):
    global rechecker
    global rechecktime
    if not info or info['handler'] is None:
        return
    if info['handler'] != pxeh and not info.get('addresses', None):
        #log.log({'info': 'Missing address information in ' + repr(info)})
        return
    handler = info['handler'].NodeHandler(info, configmanager)
    if handler.https_supported and not handler.https_cert:
        if handler.cert_fail_reason == 'unreachable':
            log.log(
                {
                    'info': '{0} with hwaddr {1} is not reachable at {2}'
                            ''.format(
                        handler.devname, info['hwaddr'], handler.ipaddr
                    )})
            # addresses data is bad, delete the offending ip
            info['addresses'] = [x for x in info.get('addresses', []) if x != handler.ipaddr]
            # TODO(jjohnson2):  rescan due to bad peer addr data?
            # not just wait around for the next announce
            return
        log.log(
            {
                'info': '{0} with hwaddr {1} at address {2} is not yet running '
                        'https, will examine later'.format(
                    handler.devname, info['hwaddr'], handler.ipaddr
                )})
        if rechecker is not None and rechecktime > util.monotonic_time() + 300:
            rechecker.cancel()
        # if cancel did not result in dead, then we are in progress
        if rechecker is None or rechecker.done():
            rechecktime = util.monotonic_time() + 300
            rechecker = tasks.spawn_task_after(300, _periodic_recheck,
                                             configmanager)
        return
    nodename, info['maccount'] = await get_nodename(configmanager, handler, info)
    if nodename:
        if handler.https_supported:
            dp = configmanager.get_node_attributes([nodename],
                                         ('pubkeys.tls_hardwaremanager',))
            lastfp = dp.get(nodename, {}).get('pubkeys.tls_hardwaremanager',
                                              {}).get('value', None)
            if util.cert_matches(lastfp, handler.https_cert):
                info['nodename'] = nodename
                known_nodes[nodename][info['hwaddr']] = info
                info['discostatus'] = 'discovered'
                return  # already known, no need for more
        tasks.spawn(eval_node(configmanager, handler, info, nodename))


def safe_detected(info):
    if 'hwaddr' not in info or not info['hwaddr']:
        return
    if info['hwaddr'] in runningevals:
        # Do not evaluate the same mac multiple times at once
        return
    runningevals[info['hwaddr']] = tasks.spawn_task(eval_detected(info))


async def eval_detected(info):
    try:
        await detected(info)
    except Exception as e:
        traceback.print_exc()
    del runningevals[info['hwaddr']]


async def detected(info):
    global rechecker
    global rechecktime
    if not cfm.config_is_ready():
        # drop processing of discovery data while configmanager is 'down'
        return
    # later, manual and CMM discovery may act on SN and/or UUID
    for service in info['services']:
        if service in nodehandlers:
            if service not in known_services:
                known_services[service] = set([])
            handler = nodehandlers[service]
            info['handler'] = handler
            break
    else:  # no nodehandler, ignore for now
        return
    if (handler and not handler.NodeHandler.adequate(info) and
            info.get('protocol', None)):
        tasks.spawn_after(10, info['protocol'].fix_info, info,
                             safe_detected)
        return
    if info['hwaddr'] in known_info and 'addresses' in info:
        # we should tee these up for parsing when an enclosure comes up
        # also when switch config parameters change, should discard
        # and there's also if wiring is fixed...
        # of course could periodically revisit known_nodes
        # replace potentially stale address info
        #TODO(jjohnson2): remove this
        # temporary workaround for XCC not doing SLP DA over dedicated port
        # bz 93219, fix submitted, but not in builds yet
        # strictly speaking, going ipv4 only legitimately is mistreated here,
        # but that should be an edge case
        oldaddr = known_info[info['hwaddr']].get('addresses', [])
        for addr in info['addresses']:
            if addr[0].startswith('fe80::'):
                break
        else:
            for addr in oldaddr:
                if addr[0].startswith('fe80::'):
                    info['addresses'].append(addr)
        if known_info[info['hwaddr']].get(
                'addresses', []) == info['addresses']:
            # if the ip addresses match, then assume no changes
            # now something resetting to defaults could, in theory
            # have the same address, but need to be reset
            # in that case, however, a user can clear pubkeys to force a check
            return
    known_info[info['hwaddr']] = info
    cfg = cfm.ConfigManager(None)
    if handler:
        handler = handler.NodeHandler(info, cfg)
        res = handler.scan()
        if inspect.isawaitable(res):
            await res
    try:
        if 'modelnumber' not in info:
            info['modelnumber'] = info['attributes']['enclosure-machinetype-model'][0]
    except (KeyError, IndexError):
        pass
    if 'modelnumber' in info:
        known_services[service].add(info['modelnumber'])
    try:
        if 'serialnumber' not in info:
            snum = info['attributes']['enclosure-serial-number'][0].strip()
            if snum:
                info['serialnumber'] = snum
    except (KeyError, IndexError):
        pass
    if 'serialnumber' in info:
        known_serials[info['serialnumber']] = info
    uuid = info.get('uuid', None)
    if uuid_is_valid(uuid):
        known_uuids[uuid][info['hwaddr']] = info
    info['otheraddresses'] = set([])
    for i4addr in info.get('attributes', {}).get('ipv4-address', []):
        info['otheraddresses'].add(i4addr)
    for i4addr in info.get('attributes', {}).get('ipv4-addresses', []):
        info['otheraddresses'].add(i4addr)
    if handler and handler.https_supported and not handler.https_cert:
        if handler.cert_fail_reason == 'unreachable':
            log.log(
                {
                    'info': '{0} with hwaddr {1} is not reachable by https '
                            'at address {2}'.format(
                        handler.devname, info['hwaddr'], handler.ipaddr
                    )})
            info['addresses'] = [x for x in info.get('addresses', []) if x != handler.ipaddr]
            return
        log.log(
            {'info':  '{0} with hwaddr {1} at address {2} is not yet running '
                      'https, will examine later'.format(
                        handler.devname, info['hwaddr'], handler.ipaddr
            )})
        if rechecker is not None and rechecktime > util.monotonic_time() + 300:
            rechecker.cancel()
        if rechecker is None or rechecker.done():
            rechecktime = util.monotonic_time() + 300
            rechecker = tasks.spawn_task_after(300, _periodic_recheck, cfg)
        unknown_info[info['hwaddr']] = info
        info['discostatus'] = 'unidentfied'
        #TODO, eventlet spawn after to recheck sooner, or somehow else
        # influence periodic recheck to shorten delay?
        return
    nodename, info['maccount'] = await get_nodename(cfg, handler, info)
    if nodename and handler and handler.https_supported:
        dp = cfg.get_node_attributes([nodename],
                                     ('pubkeys.tls_hardwaremanager', 'id.uuid', 'discovery.policy'))
        dp = dp.get(nodename, {})
        lastfp = dp.get('pubkeys.tls_hardwaremanager',
                                          {}).get('value', None)
        if util.cert_matches(lastfp, handler.https_cert):
            info['nodename'] = nodename
            known_nodes[nodename][info['hwaddr']] = info
            info['discostatus'] = 'discovered'
            uuid = info.get('uuid', None)
            if uuid:
                storeuuid = dp.get('id.uuid', {}).get('value', None)
                if not storeuuid:
                    discop = dp.get('discovery.policy', {}).get('value', '')
                    if discop:
                        policies = set(discop.split(','))
                    else:
                        policies = set([])
                    if policies & {'open', 'permissive'}:
                        cfg.set_node_attributes({nodename: {'id.uuid': info['uuid']}})
            return  # already known, no need for more
    #TODO(jjohnson2): We might have to get UUID for certain searches...
    #for now defer probe until inside eval_node.  We might not have
    #a nodename without probe in the future.
    if nodename and handler:
        await eval_node(cfg, handler, info, nodename)
    elif handler:
        #log.log(
        #    {'info': 'Detected unknown {0} with hwaddr {1} at '
        #             'address {2}'.format(
        #                handler.devname, info['hwaddr'], handler.ipaddr
        #              )})
        info['discostatus'] = 'unidentified'
        unknown_info[info['hwaddr']] = info



def b64tohex(b64str):
    bd = base64.b64decode(b64str)
    bd = bytearray(bd)
    return ''.join(['{0:02x}'.format(x) for x in bd])


def get_enclosure_chain_head(nodename, cfg):
    ne = True
    members = [nodename]
    while ne:
        ne = cfg.get_node_attributes(
            nodename, 'enclosure.extends').get(nodename, {}).get(
            'enclosure.extends', {}).get('value', None)
        if not ne:
            return nodename
        if ne in members:
            raise exc.InvalidArgumentException(
                'Circular chain that includes ' + nodename)
        if not cfg.is_node(ne):
            raise exc.InvalidArgumentException(
                '{0} is chained to nonexistent node {1} '.format(
                    nodename, ne))
        nodename = ne
        members.append(nodename)
    return nodename


def get_chained_smm_name(nodename, cfg, handler, nl=None, checkswitch=True):
    # nodename is the head of the chain, cfg is a configmanager, handler
    # is the handler of the current candidate, nl is optional indication
    # of the next link in the chain, checkswitch can disable the switch
    # search if not indicated by current situation
    # returns the new name and whether it has been securely validated or not
    # first we check to see if directly connected
    mycert = handler.https_cert
    if checkswitch:
        fprints = macmap.get_node_fingerprints(nodename, cfg)
        for fprint in fprints:
            if util.cert_matches(fprint[0], mycert):
                # ok we have a direct match, it is this node
                return nodename, fprint[1]
    # ok, unable to get it, need to traverse the chain from the beginning
    if not nl:
        nl = list(cfg.filter_node_attributes(
            'enclosure.extends=' + nodename))
    while nl:
        if len(nl) != 1:
            raise exc.InvalidArgumentException('Multiple enclosures trying to '
                                               'extend a single enclosure')
        cd = cfg.get_node_attributes(nodename, ['hardwaremanagement.manager',
                                                'pubkeys.tls_hardwaremanager'])
        pkey = cd[nodename].get('pubkeys.tls_hardwaremanager', {}).get(
            'value', None)
        if not pkey:
            # We cannot continue through a break in the chain
            return None, False
        smmaddr = cd.get(nodename, {}).get('hardwaremanagement.manager', {}).get('value', None)
        if not smmaddr:
            return None, False
        smmaddr = smmaddr.split('/', 1)[0]
        if pkey:
            cv = util.TLSCertVerifier(
                cfg, nodename, 'pubkeys.tls_hardwaremanager').verify_cert
            for fprint in get_smm_neighbor_fingerprints(smmaddr, cv):
                if util.cert_matches(fprint, mycert):
                    # a trusted chain member vouched for the cert
                    # so it's validated
                    return nl[0], True
            # advance down the chain by one and try again
        nodename = nl[0]
        nl = list(cfg.filter_node_attributes(
            'enclosure.extends=' + nodename))
    return None, False


def get_smm_neighbor_fingerprints(smmaddr, cv):
    if ':' in smmaddr:
        smmaddr = '[{0}]'.format(smmaddr)
    wc = webclient.SecureHTTPConnection(smmaddr, verifycallback=cv)
    try:
        neighs = wc.grab_json_response('/scripts/neighdata.json')
    except Exception:
        log.log({'error': 'Failure getting LLDP information from {}'.format(smmaddr)})
        return
    if not neighs:
        return
    for neigh in neighs:
        if 'sha256' not in neigh:
            continue
        yield 'sha256$' + b64tohex(neigh['sha256'])

def get_nodename_sysdisco(cfg, handler, info):
    switchname = info['forwarder_server']
    switchnode = None
    nl = cfg.filter_node_attributes('net.*switch=' + switchname)
    brokenattrs = False
    for n in nl:
        na = cfg.get_node_attributes(n, 'net.*switchport').get(n, {})
        for sp in na:
            pv = na[sp].get('value', '')
            if pv and macmap._namesmatch(info['port'], pv):
                if switchnode:
                    log.log({'error': 'Ambiguous port information between {} and {}'.format(switchnode, n)})
                    brokenattrs = True
                else:
                    switchnode = n
                break
    if brokenattrs or not switchnode:
        return None
    if 'enclosure_num' not in info:
        return switchnode
    chainlen = info['enclosure_num']
    currnode = switchnode
    while chainlen > 1:
        nl = list(cfg.filter_node_attributes('enclosure.extends=' + currnode))
        if len(nl) > 1:
            log.log({'error': 'Multiple enclosures specify extending ' + currnode})
            return None
        if len(nl) == 0:
            log.log({'error': 'No enclosures specify extending ' + currnode + ' but an enclosure seems to be extending it'})
            return None
        currnode = nl[0]
        chainlen -= 1
    if info['type'] == 'lenovo-smm2':
        return currnode
    else:
        baynum = info['bay']
        nl = cfg.filter_node_attributes('enclosure.manager=' + currnode)
        nl = list(cfg.filter_node_attributes('enclosure.bay={0}'.format(baynum), nl))
        if len(nl) == 1:
            return nl[0]


async def get_nodename(cfg, handler, info):
    nodename = None
    maccount = None
    info['verified'] = False
    if not handler:
        return None, None
    if handler.https_supported:
        currcert = handler.https_cert
        if not currcert:
            info['discofailure'] = 'nohttps'
            return None, None
        currprint = util.get_fingerprint(currcert, 'sha256')
        nodename = nodes_by_fprint.get(currprint, None)
        if not nodename:
            # Try SHA512 as well
            currprint = util.get_fingerprint(currcert)
            nodename = nodes_by_fprint.get(currprint, None)
    if not nodename:
        curruuid = info.get('uuid', None)
        if uuid_is_valid(curruuid):
            nodename = nodes_by_uuid.get(curruuid, None)
            if nodename is None:
                _map_unique_ids()
                nodename = nodes_by_uuid.get(curruuid, None)
    if not nodename and info['handler'] == pxeh:
        enrich_pxe_info(info)
        nodename = info.get('nodename', None)
    if 'forwarder_server' in info:
        # this has been registered by a remote discovery registry,
        # thus verification and specific location is fixed
        if nodename:
            return nodename, None
        return get_nodename_sysdisco(cfg, handler, info), None
    if not nodename:
        # Ok, see if it is something with a chassis-uuid and discover by
        # chassis
        nodename = get_nodename_from_enclosures(cfg, info)
    if not nodename and handler.devname in ('SMM', 'SMM3'):
        nodename = get_nodename_from_chained_smms(cfg, handler, info)
    if not nodename:  # as a last resort, search switches for info
        # This is the slowest potential operation, so we hope for the
        # best to occur prior to this
        nodename, macinfo = await macmap.find_nodeinfo_by_mac(info['hwaddr'], cfg)
        maccount = macinfo['maccount']
        if nodename:
            if handler.devname in ('SMM', 'SMM3'):
                nl = list(cfg.filter_node_attributes(
                            'enclosure.extends=' + nodename))
                if nl:
                    # We found an SMM, and it's in a chain per configuration
                    # we need to ask the switch for the fingerprint to see
                    # if we have a match or not
                    newnodename, v = get_chained_smm_name(nodename, cfg,
                                                          handler, nl)
                    if newnodename:
                        # while this started by switch, it was disambiguated
                        info['verified'] = v
                        return newnodename, None
                    else:
                        errorstr = ('Attempt to discover SMM in chain but '
                                   'unable to follow chain to the specific '
                                   'SMM, it may be waiting on an upstream '
                                   'SMM, chain starts with {0}'.format(
                                       nodename))
                        log.log({'error': errorstr})
                        return None, None
        if (nodename and
                not handler.discoverable_by_switch(macinfo['maccount'])):
            if handler.devname in ('SMM', 'SMM3'):
                errorstr = 'Attempt to discover SMM by switch, but chained ' \
                           'topology or incorrect net attributes detected, ' \
                           'which is not compatible with switch discovery ' \
                           'of SMM, nodename would have been ' \
                           '{0}'.format(nodename)
                log.log({'error': errorstr})
                return None, None
    return nodename, maccount


def get_nodename_from_chained_smms(cfg, handler, info):
    nodename = None
    for fprint in get_smm_neighbor_fingerprints(
            handler.ipaddr, lambda x: True):
        if fprint in nodes_by_fprint:
            # need to chase the whole chain
            # to support either direction
            chead = get_enclosure_chain_head(nodes_by_fprint[fprint],
                                             cfg)
            newnodename, v = get_chained_smm_name(
                chead, cfg, handler, checkswitch=False)
            if newnodename:
                info['verified'] = v
                nodename = newnodename
    return nodename

def get_node_guess_by_uuid(uuid):
    for mac in known_uuids.get(uuid, {}):
        nodename = known_uuids[uuid][mac].get('nodename', None)
        if nodename:
            return nodename
    return None

def get_node_by_uuid_or_mac(uuidormac):
    node = pxe.macmap.get(uuidormac, None)
    if node is not None:
        return node
    return nodes_by_uuid.get(uuidormac, None)

def get_nodename_from_enclosures(cfg, info):
    nodename = None
    cuuid = info.get('enclosure.uuid', None)
    if not cuuid:
        cuuid = info.get('attributes', {}).get('chassis-uuid', [None])[0]
    if cuuid and cuuid in nodes_by_uuid:
        encl = nodes_by_uuid[cuuid]
        bay = info.get('enclosure.bay', None)
        if bay:
            tnl = cfg.filter_node_attributes('enclosure.manager=' + encl)
            tnl = list(
                cfg.filter_node_attributes('enclosure.bay={0}'.format(bay),
                                           tnl))
            if len(tnl) == 1:
                # This is not a secure assurance, because it's by
                # uuid instead of a key
                nodename = tnl[0]
    return nodename


def search_smms_by_cert(currsmm, cert, cfg):
    neighs = []
    cv = util.TLSCertVerifier(
        cfg, currsmm, 'pubkeys.tls_hardwaremanager').verify_cert
    try:
        cd = cfg.get_node_attributes(currsmm, ['hardwaremanagement.manager',
                                               'pubkeys.tls_hardwaremanager'])
        smmaddr = cd.get(currsmm, {}).get('hardwaremanagement.manager', {}).get('value', None)
        if not smmaddr:
            smmaddr = currsmm
        wc = webclient.SecureHTTPConnection(smmaddr, verifycallback=cv)
        neighs = wc.grab_json_response('/scripts/neighdata.json')
    except Exception:
        return None
    for neigh in neighs:
        fprint = neigh.get('sha384', None)
        if fprint and fprint.endswith('AA=='):
            fprint = fprint[:-4]
        if fprint and util.cert_matches(fprint, cert):
            port = neigh.get('port', None)
            if port is not None:
                bay = port + 1
                nl = list(
                    cfg.filter_node_attributes('enclosure.manager=' + currsmm))
                nl = list(
                    cfg.filter_node_attributes('enclosure.bay={}'.format(bay), nl))
                if len(nl) == 1:
                    return currsmm, bay, nl[0]
                return currsmm, bay, None
    exnl = list(cfg.filter_node_attributes('enclosure.extends=' + currsmm))
    if len(exnl) == 1:
        return search_smms_by_cert(exnl[0], cert, cfg)


async def eval_node(cfg, handler, info, nodename, manual=False):
    try:
        handler.probe()  # unicast interrogation as possible to get more data
        # switch concurrently
        # do some preconfig, for example, to bring a SMM online if applicable
        await handler.preconfig(nodename)
    except Exception as e:
        unknown_info[info['hwaddr']] = info
        info['discostatus'] = 'unidentified'
        errorstr = 'An error occured during discovery, check the ' \
                   'trace and stderr logs, mac was {0} and ip was {1}' \
                   ', the node or the containing enclosure was {2}' \
                   ''.format(info['hwaddr'], handler.ipaddr, nodename)
        traceback.print_exc()
        if manual:
            raise exc.InvalidArgumentException(errorstr)
        log.log({'error': errorstr})
        return
    # first, if had a bay, it was in an enclosure.  If it was discovered by
    # switch, it is probably the enclosure manager and not
    # the node directly.  switch is ambiguous and we should leave it alone
    if 'enclosure.bay' in info and handler.is_enclosure:
        unknown_info[info['hwaddr']] = info
        info['discostatus'] = 'unidentified'
        log.log({'error': 'Something that is an enclosure reported a bay, '
                          'not possible'})
        if manual:
            raise exc.InvalidArgumentException()
        return
    nl = list(cfg.filter_node_attributes('enclosure.manager=' + nodename))
    if not handler.is_enclosure and nl:
        # The specified node is an enclosure (has nodes mapped to it), but
        # what we are talking to is *not* an enclosure
        # might be ambiguous, need to match chassis-uuid as well..
        match = search_smms_by_cert(nodename, handler.https_cert, cfg)
        if match:
            info['verfied'] = True
            info['enclosure.bay'] = match[1]
            if match[2]:
                if not await discover_node(cfg, handler, info, match[2], manual):
                    pending_nodes[match[2]] = info
                return
        if 'enclosure.bay' not in info:
            unknown_info[info['hwaddr']] = info
            info['discostatus'] = 'unidentified'
            errorstr = '{2} with mac {0} is in {1}, but unable to ' \
                       'determine bay number'.format(info['hwaddr'],
                                                     nodename,
                                                     handler.ipaddr)
            if manual:
                raise exc.InvalidArgumentException(errorstr)
            log.log({'error': errorstr})
            return
        enl = list(cfg.filter_node_attributes('enclosure.extends=' + nodename))
        if enl:
            # ambiguous SMM situation according to the configuration, we need
            # to match uuid
            encuuid = info['attributes'].get('chassis-uuid', None)
            if encuuid:
                encuuid = encuuid[0]
                enl = list(cfg.filter_node_attributes('id.uuid=' + encuuid))
                if len(enl) != 1:
                    # errorstr = 'No SMM by given UUID known, *yet*'
                    # if manual:
                    #     raise exc.InvalidArgumentException(errorstr)
                    # log.log({'error': errorstr})
                    if encuuid in pending_by_uuid:
                        pending_by_uuid[encuuid].append(info)
                    else:
                        pending_by_uuid[encuuid] = [info]
                    return
                # We found the real smm, replace the list with the actual smm
                # to continue
                nl = list(cfg.filter_node_attributes(
                    'enclosure.manager=' + enl[0]))
            else:
                errorstr = 'Chained SMM configuration with older XCC, ' \
                           'unable to perform zero power discovery'
                if manual:
                    raise exc.InvalidArgumentException(errorstr)
                log.log({'error': errorstr})
                return
        # search for nodes fitting our description using filters
        # lead with the most specific to have a small second pass
        nl = list(cfg.filter_node_attributes(
            'enclosure.bay={0}'.format(info['enclosure.bay']), nl))
        if len(nl) != 1:
            info['discofailure'] = 'ambigconfig'
            if len(nl):
                errorstr = 'The following nodes have duplicate ' \
                           'enclosure attributes: ' + ','.join(nl)

            else:
                errorstr = 'The {0} in enclosure {1} bay {2} does not ' \
                           'seem to be a defined node ({3})'.format(
                                        handler.devname, nodename,
                                        info['enclosure.bay'],
                                        handler.ipaddr,
                                    )
            if manual:
                raise exc.InvalidArgumentException(errorstr)
            log.log({'error': errorstr})
            unknown_info[info['hwaddr']] = info
            info['discostatus'] = 'unidentified'
            return
        nodename = nl[0]
        if not await discover_node(cfg, handler, info, nodename, manual):
            # store it as pending, assuming blocked on enclosure
            # assurance...
            pending_nodes[nodename] = info
    else:
        # we can and did accurately discover by switch or in enclosure
        # but... is this really ok?  could be on an upstream port or
        # erroneously put in the enclosure with no nodes yet
        # so first, see if the candidate node is a chain host
        if not manual:
            if info.get('maccount', False):
                # discovery happened through switch
                nl = list(cfg.filter_node_attributes(
                    'enclosure.extends=' + nodename))
                if nl:
                    # The candidate nodename is the head of a chain, we must
                    # validate the smm certificate by the switch
                    fprints = macmap.get_node_fingerprints(nodename, cfg)
                    for fprint in fprints:
                        if util.cert_matches(fprint[0], handler.https_cert):
                            if not await discover_node(cfg, handler, info,
                                                 nodename, manual):
                                pending_nodes[nodename] = info
                            return
            if (info.get('maccount', False) and
                    not handler.discoverable_by_switch(info['maccount'])):
                errorstr = 'The detected node {0} was detected using switch, ' \
                           'however the relevant port has too many macs learned ' \
                           'for this type of device ({1}) to be discovered by ' \
                           'switch.  If this should be an enclosure, make sure there are ' \
                           'defined nodes for the enclosure'.format(nodename, handler.devname)
                log.log({'error': errorstr})
                return
        if not await discover_node(cfg, handler, info, nodename, manual):
            pending_nodes[nodename] = info


async def discover_node(cfg, handler, info, nodename, manual):
    if manual:
        if not cfg.is_node(nodename):
            raise exc.InvalidArgumentException(
                '{0} is not a defined node, must be defined before an '
                'endpoint may be assigned to it'.format(nodename))
        if handler.https_supported:
            currcert = handler.https_cert
            if currcert:
                currprint = util.get_fingerprint(currcert, 'sha256')
                prevnode = nodes_by_fprint.get(currprint, None)
                if prevnode and prevnode != nodename:
                    raise exc.InvalidArgumentException(
                    'Attempt to assign {0} conflicts with existing node {1} '
                    'based on TLS certificate.'.format(nodename, prevnode))
    known_nodes[nodename][info['hwaddr']] = info
    if info['hwaddr'] in unknown_info:
        del unknown_info[info['hwaddr']]
    info['discostatus'] = 'identified'
    dp = cfg.get_node_attributes(
        [nodename], ('discovery.policy', 'id.uuid',
                     'pubkeys.tls_hardwaremanager'))
    policy = dp.get(nodename, {}).get('discovery.policy', {}).get(
        'value', None)
    if policy is None:
        policy = ''
    policies = set(policy.split(','))
    lastfp = dp.get(nodename, {}).get('pubkeys.tls_hardwaremanager',
                                      {}).get('value', None)
    # TODO(jjohnson2): permissive requires we guarantee storage of
    # the pubkeys, which is deferred for a little bit
    # Also, 'secure', when we have the needed infrastructure done
    # in some product or another.
    curruuid = info.get('uuid', False)
    if 'pxe' in policies and info['handler'] == pxeh:
        return do_pxe_discovery(cfg, handler, info, manual, nodename, policies)
    elif ('permissive' in policies and handler.https_supported and lastfp and
            not util.cert_matches(lastfp, handler.https_cert) and not manual):
        info['discofailure'] = 'fingerprint'
        log.log({'info': 'Detected replacement of {0} with existing '
                         'fingerprint and permissive discovery policy, not '
                         'doing discovery unless discovery.policy=open or '
                         'pubkeys.tls_hardwaremanager attribute is cleared '
                         'first'.format(nodename)})
        return False  # With a permissive policy, do not discover new
    elif policies & set(('open', 'permissive', 'verified')) or manual:
        if 'verified' in policies:
            if not handler.https_supported or not util.cert_matches(info['fingerprint'], handler.https_cert):
                log.log({'info': 'Detected replacement of {0} without verified '
                         'fingerprint and discovery policy is set to verified, not '
                         'doing discovery unless discovery.policy=open or '
                         'pubkeys.tls_hardwaremanager attribute is cleared '
                         'first'.format(nodename)})
                return False
        info['nodename'] = nodename
        if info['handler'] == pxeh:
            return do_pxe_discovery(cfg, handler, info, manual, nodename, policies)
        elif manual or not util.cert_matches(lastfp, handler.https_cert):
            # only 'discover' if it is not the same as last time
            try:
                await handler.config(nodename)
            except Exception as e:
                info['discofailure'] = 'bug'
                if manual:
                    raise
                log.log(
                    {'error':
                         'Error encountered trying to set up {0}, {1}'.format(
                             nodename, str(e))})
                traceback.print_exc()
                return False
            nodeconfig = cfg.get_node_attributes(nodename, 'discovery.nodeconfig')
            nodeconfig = nodeconfig.get(nodename, {}).get('discovery.nodeconfig', {}).get('value', None)
            if nodeconfig:
                nodeconfig = shlex.split(nodeconfig)
            newnodeattribs = {}
            if list(cfm.list_collective()):
                # We are in a collective, check collective.manager
                cmc = cfg.get_node_attributes(nodename, 'collective.manager')
                cm = cmc.get(nodename, {}).get('collective.manager', {}).get('value', None)
                if not cm:
                    # Node is being discovered in collective, but no collective.manager, default
                    # to the collective member actually able to execute the discovery
                    newnodeattribs['collective.manager'] = collective.get_myname()
            if 'uuid' in info:
                newnodeattribs['id.uuid'] = info['uuid']
            if 'serialnumber' in info:
                newnodeattribs['id.serial'] = info['serialnumber']
            if 'modelnumber' in info:
                newnodeattribs['id.model'] = info['modelnumber']
            if handler.https_cert:
                newnodeattribs['pubkeys.tls_hardwaremanager'] = \
                    util.get_fingerprint(handler.https_cert, 'sha256')
            if newnodeattribs:
                currattrs = cfg.get_node_attributes(nodename, newnodeattribs)
                for checkattr in newnodeattribs:
                    checkval = currattrs.get(nodename, {}).get(checkattr, {}).get('value', None)
                    if checkval != newnodeattribs[checkattr]:
                        await cfg.set_node_attributes({nodename: newnodeattribs})
                        break
            log.log({'info': 'Discovered {0} ({1})'.format(nodename,
                                                          handler.devname)})
            if nodeconfig or handler.current_cert_self_signed():
                bmcaddr = cfg.get_node_attributes(nodename, 'hardwaremanagement.manager')
                bmcaddr = bmcaddr.get(nodename, {}).get('hardwaremanagement.manager', {}).get('value', '')
                if not bmcaddr:
                    log.log({'error': 'Unable to get BMC address for {0]'.format(nodename)})
                else:
                    bmcaddr = bmcaddr.split('/', 1)[0]
                    await wait_for_connection(bmcaddr)
                    socket.getaddrinfo(bmcaddr, 443)
            if nodeconfig:
                    await util.check_call(['/opt/confluent/bin/nodeconfig', nodename] + nodeconfig)
                    log.log({'info': 'Configured {0} ({1})'.format(nodename,
                                                          handler.devname)})
            if verification and handler.current_cert_self_signed():
                handler.autosign_certificate()

        info['discostatus'] = 'discovered'
        for i in pending_by_uuid.get(curruuid, []):
            tasks.spawn(_recheck_single_unknown_info(cfg, i))
        try:
            del pending_by_uuid[curruuid]
        except KeyError:
            pass
        return True
    if info['handler'] == pxeh:
        olduuid = dp.get(nodename, {}).get('id.uuid', {}).get(
            'value', '')
        if olduuid.lower() != info['uuid']:
            log.log({'info': 'Detected {0}, but discovery.policy is not set to a '
                            'value allowing discovery (open, permissive, or pxe)'.format(
                                nodename)})
            info['discofailure'] = 'policy'
    else:
        log.log({'info': 'Detected {0}, but discovery.policy is not set to a '
                         'value allowing discovery (open or permissive)'.format(
                            nodename)})
        info['discofailure'] = 'policy'
    return False

async def wait_for_connection(bmcaddr):
    cloop = asyncio.get_running_loop()
    expiry = 75 + util.monotonic_time()
    while util.monotonic_time() < expiry:
        for addrinf in await cloop.getaddrinfo(bmcaddr, 443, proto=socket.IPPROTO_TCP):
            try:
                tsock = socket.socket(addrinf[0])
                tsock.settimeout(1)
                tsock.connect(addrinf[4])
                return
            except OSError:
                continue
        await asyncio.sleep(1)

def do_pxe_discovery(cfg, handler, info, manual, nodename, policies):
    # use uuid based scheme in lieu of tls cert, ideally only
    # for stateless 'discovery' targets like pxe, where data does not
    # change
    uuidinfo = cfg.get_node_attributes(nodename, ['id.uuid', 'id.serial', 'id.model', 'net*.hwaddr', 'net*.bootable'])
    if manual or policies & set(('open', 'pxe')):
        enrich_pxe_info(info)
        attribs = {}
        olduuid = uuidinfo.get(nodename, {}).get('id.uuid', None)
        if isinstance(olduuid, dict):
            olduuid = olduuid.get('value', None)
        uuid = info.get('uuid', None)
        if uuid and uuid != olduuid:
            attribs['id.uuid'] = info['uuid']
        sn = info.get('serialnumber', None)
        mn = info.get('modelnumber', None)
        if sn and sn != uuidinfo.get(nodename, {}).get('id.serial', None):
            attribs['id.serial'] = sn
        if mn and mn != uuidinfo.get(nodename, {}).get('id.model', None):
            attribs['id.model'] = mn
        for attrname in uuidinfo.get(nodename, {}):
            if attrname.endswith('.bootable') and uuidinfo[nodename][attrname].get('value', None):
                newattrname = attrname[:-8] + 'hwaddr'
                oldhwaddr = uuidinfo.get(nodename, {}).get(newattrname, {}).get('value', None)
                if info['hwaddr'] != oldhwaddr:
                    attribs[newattrname] = info['hwaddr']
        if attribs:
            currattrs = cfg.get_node_attributes(nodename, attribs)
            for checkattr in attribs:
                checkval = currattrs.get(nodename, {}).get(checkattr, {}).get('value', None)
                if checkval != attribs[checkattr]:
                    cfg.set_node_attributes({nodename: attribs})
                    break
    if info['uuid'] in known_pxe_uuids:
        return True
    if uuid_is_valid(info['uuid']):
        known_pxe_uuids[info['uuid']] = nodename
    #log.log({'info': 'Detected {0} ({1} with mac {2})'.format(
    #    nodename, handler.devname, info['hwaddr'])})
    return True


attribwatcher = None
nodeaddhandler = None
needaddhandled = False


async def _handle_nodelist_change(configmanager):
    global needaddhandled
    global nodeaddhandler
    macmap.vintage = 0  # the current mac map is probably inaccurate
    await _recheck_nodes((), configmanager)
    if needaddhandled:
        needaddhandled = False
        nodeaddhandler = tasks.spawn_task(_handle_nodelist_change(configmanager))
    else:
        nodeaddhandler = None


async def newnodes(added, deleting, renamed, configmanager):
    global attribwatcher
    global needaddhandled
    global nodeaddhandler
    alldeleting = set(deleting) | set(renamed)
    for node in alldeleting:
        if node not in known_nodes:
            continue
        for mac in known_nodes[node]:
            if mac in known_info:
                del known_info[mac]
        del known_nodes[node]
    _map_unique_ids()
    configmanager.remove_watcher(attribwatcher)
    allnodes = configmanager.list_nodes()
    attribwatcher = configmanager.watch_attributes(
        allnodes, ('discovery.policy', 'net*.switch',
                   'hardwaremanagement.manager', 'net*.switchport',
                   'id.uuid', 'pubkeys.tls_hardwaremanager',
                   'net*.bootable'), _recheck_nodes)
    if nodeaddhandler:
        needaddhandled = True
    else:
        nodeaddhandler = tasks.spawn_task(_handle_nodelist_change(configmanager))



rechecker = None
rechecktime = None
rechecklock = asyncio.Lock()

async def _periodic_recheck(configmanager):
    global rechecker
    global rechecktime
    rechecker = None
    try:
        await _recheck_nodes((), configmanager)
    except Exception:
        traceback.print_exc()
        log.log({'error': 'Unexpected error during discovery, check debug '
                          'logs'})
    # if rechecker is set, it means that an accelerated schedule
    # for rechecker was requested in the course of recheck_nodes
    if rechecker is None:
        rechecktime = util.monotonic_time() + 900
        rechecker = tasks.spawn_task_after(900, _periodic_recheck,
                                         configmanager)


async def rescan():
    _map_unique_ids()
    global scanner
    if scanner:
        return
    else:
        scanner = tasks.spawn_task(blocking_scan())
    await remotescan()

async def remotescan():
    mycfm = cfm.ConfigManager(None)
    myname = collective.get_myname()
    for remagent in get_subscriptions():
        try:
            await affluent.renotify_me(remagent, mycfm, myname)
        except Exception as e:
            log.log({'error': 'Unexpected problem asking {} for discovery notifications'.format(remagent)})


async def blocking_scan():
    global scanner
    slpscan = tasks.spawn_task(slp.active_scan(safe_detected, slp))
    ssdpscan = tasks.spawn_task(ssdp.active_scan(safe_detected, ssdp))
    await slpscan
    await ssdpscan
    #ssdpscan.wait()
    scanner = None

def start_detection():
    global attribwatcher
    global rechecker
    global rechecktime
    _map_unique_ids()
    cfg = cfm.ConfigManager(None)
    allnodes = cfg.list_nodes()
    attribwatcher = cfg.watch_attributes(
        allnodes, ('discovery.policy', 'net*.switch',
                   'hardwaremanagement.manager', 'net*.switchport', 'id.uuid',
                   'pubkeys.tls_hardwaremanager'), _recheck_nodes)
    cfg.watch_nodecollection(newnodes)
    autosense = cfm.get_global('discovery.autosense')
    if autosense or autosense is None:
        start_autosense()
    if rechecker is None:
        rechecktime = util.monotonic_time() + 900
        rechecker = tasks.spawn_task_after(900, _periodic_recheck, cfg)
    tasks.spawn(ssdp.snoop(safe_detected, None, ssdp, get_node_by_uuid_or_mac))

def stop_autosense():
    for watcher in list(autosensors):
        watcher.cancel()
        autosensors.discard(watcher)

def start_autosense():
    autosensors.add(tasks.spawn_task(slp.snoop(safe_detected, slp)))
    #autosensors.add(eventlet.spawn(mdns.snoop, safe_detected, mdns))
    tasks.spawn(pxe.snoop(safe_detected, pxe, get_node_guess_by_uuid))
    #autosensors.add(eventlet.spawn(pxe.snoop, safe_detected, pxe, get_node_guess_by_uuid))
    tasks.spawn(remotescan())


nodes_by_fprint = {}
nodes_by_uuid = {}
known_pxe_uuids = {}

def _map_unique_ids(nodes=None):
    global nodes_by_uuid
    global nodes_by_fprint
    global known_pxe_uuids
    # Map current known ids based on uuid and fingperprints for fast lookup
    cfg = cfm.ConfigManager(None)
    if nodes is None:
        nodes_by_uuid = {}
        nodes_by_fprint = {}
        known_pxe_uuids = {}
        nodes = cfg.list_nodes()
    bigmap = cfg.get_node_attributes(nodes,
                                     ('id.uuid',
                                      'pubkeys.tls_hardwaremanager'))
    for uuid in list(nodes_by_uuid):
        node = nodes_by_uuid[uuid]
        if node in bigmap:
            del nodes_by_uuid[uuid]
    for uuid in list(known_pxe_uuids):
        node = known_pxe_uuids[uuid]
        if node in bigmap:
            del known_pxe_uuids[uuid]
    for fprint in list(nodes_by_fprint):
        node = nodes_by_fprint[fprint]
        if node in bigmap:
            del nodes_by_fprint[fprint]
    for node in bigmap:
        uuid = bigmap[node].get('id.uuid', {}).get('value', '').lower()
        if uuid_is_valid(uuid):
            nodes_by_uuid[uuid] = node
            known_pxe_uuids[uuid] = node
        fprint = bigmap[node].get(
            'pubkeys.tls_hardwaremanager', {}).get('value', None)
        if fprint:
            nodes_by_fprint[fprint] = node


async def main():
    start_detection()
    while True:
        await asyncio.sleep(30)

if __name__ == '__main__':
    asyncio.get_event_loop().run_until_complete(main())
