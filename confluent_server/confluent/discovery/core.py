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

import confluent.config.configmanager as cfm
import confluent.discovery.protocols.pxe as pxe
#import confluent.discovery.protocols.ssdp as ssdp
import confluent.discovery.protocols.slp as slp
import confluent.discovery.handlers.imm as imm
import confluent.discovery.handlers.pxe as pxeh
import confluent.discovery.handlers.smm as smm
import confluent.discovery.handlers.xcc as xcc
import confluent.exceptions as exc
import confluent.log as log
import confluent.messages as msg
import confluent.networking.macmap as macmap
import confluent.noderange as noderange
import confluent.util as util
import traceback

import eventlet
import eventlet.greenpool
import eventlet.semaphore

class nesteddict(dict):

    def __missing__(self, key):
        v = self[key] = nesteddict()
        return v

nodehandlers = {
    'service:lenovo-smm': smm,
    'service:management-hardware.Lenovo:lenovo-xclarity-controller': xcc,
    'service:management-hardware.IBM:integrated-management-module2': imm,
    'pxe-client': pxeh,
}

servicenames = {
    'pxe-client': 'pxe-client',
    'service:lenovo-smm': 'lenovo-smm',
    'service:management-hardware.Lenovo:lenovo-xclarity-controller': 'lenovo-xcc',
    'service:management-hardware.IBM:integrated-management-module2': 'lenovo-imm2',
}

servicebyname = {
    'pxe-client': 'pxe-client',
    'lenovo-smm': 'service:lenovo-smm',
    'lenovo-xcc': 'service:management-hardware.Lenovo:lenovo-xclarity-controller',
    'lenovo-imm2': 'service:management-hardware.IBM:integrated-management-module2',
}

discopool = eventlet.greenpool.GreenPool(500)
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
                                '20202020-2020-2020-2020-202020202020')


def send_discovery_datum(info):
    addresses = info.get('addresses', [])
    if info['handler'] == pxeh:
        enrich_pxe_info(info)
    yield msg.KeyValueData({'nodename': info.get('nodename', '')})
    yield msg.KeyValueData({'ipaddrs': [x[0] for x in addresses]})
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
    if 'enclosure.bay' in info:
        yield msg.KeyValueData({'bay': int(info['enclosure.bay'])})
    yield msg.KeyValueData({'macs': [info.get('hwaddr', '')]})
    types = []
    for infotype in info.get('services', []):
        if infotype in servicenames:
            types.append(servicenames[infotype])
    yield msg.KeyValueData({'types': types})


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


def handle_api_request(configmanager, inputdata, operation, pathcomponents):
    if operation == 'retrieve':
        return handle_read_api_request(pathcomponents)
    elif (operation in ('update', 'create') and
            pathcomponents == ['discovery', 'rescan']):
        if inputdata != {'rescan': 'start'}:
            raise exc.InvalidArgumentException()
        rescan()
        return (msg.KeyValueData({'rescan': 'started'}),)
    elif (operation in ('update', 'create')):
        if 'node' not in inputdata:
            raise exc.InvalidArgumentException('Missing node name in input')
        _, queryparms, _, _ = _parameterize_path(pathcomponents[1:])
        if 'by-mac' not in queryparms:
            raise exc.InvalidArgumentException('Must target using "by-mac"')
        mac = queryparms['by-mac'].replace('-', ':')
        if mac not in known_info:
            raise exc.NotFoundException('{0} not found'.format(mac))
        info = known_info[mac]
        handler = info['handler'].NodeHandler(info, configmanager)
        eval_node(configmanager, handler, info, inputdata['node'],
                  manual=True)
        return [msg.AssignedResource(inputdata['node'])]
    raise exc.NotImplementedException(
        'Unable to {0} to {1}'.format(operation, '/'.join(pathcomponents)))


def handle_read_api_request(pathcomponents):
    # TODO(jjohnson2): This should be more generalized...
    #  odd indexes into components are 'by-'*, even indexes
    # starting at 2 are parameters to previous index
    subcats, queryparms, indexof, coll = _parameterize_path(pathcomponents[1:])
    if len(pathcomponents) == 1:
        dirlist = [msg.ChildCollection(x + '/') for x in sorted(list(subcats))]
        dirlist.append(msg.ChildCollection('rescan'))
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


def _recheck_nodes(nodeattribs, configmanager):
    if rechecklock.locked():
        # if already in progress, don't run again
        # it may make sense to schedule a repeat, but will try the easier and less redundant way first
        return
    with rechecklock:
        return _recheck_nodes_backend(nodeattribs, configmanager)

def _recheck_nodes_backend(nodeattribs, configmanager):
    global rechecker
    _map_unique_ids(nodeattribs)
    # for the nodes whose attributes have changed, consider them as potential
    # strangers
    for node in nodeattribs:
        if node in known_nodes:
            for somemac in known_nodes[node]:
                unknown_info[somemac] = known_nodes[node][somemac]
                unknown_info[somemac]['discostatus'] = 'unidentified'
    # Now we go through ones we did not find earlier
    for mac in list(unknown_info):
        try:
            _recheck_single_unknown(configmanager, mac)
        except Exception:
            traceback.print_exc()
            continue
    # now we go through ones that were identified, but could not pass
    # policy or hadn't been able to verify key
    for nodename in pending_nodes:
        info = pending_nodes[nodename]
        try:
            handler = info['handler'].NodeHandler(info, configmanager)
            discopool.spawn_n(eval_node, configmanager, handler, info, nodename)
        except Exception:
            traceback.print_exc()
            log.log({'error': 'Unexpected error during discovery of {0}, check debug '
                              'logs'.format(nodename)})


def _recheck_single_unknown(configmanager, mac):
    global rechecker
    global rechecktime
    info = unknown_info.get(mac, None)
    if not info:
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
        if rechecker is None or rechecker.dead:
            rechecktime = util.monotonic_time() + 300
            rechecker = eventlet.spawn_after(300, _periodic_recheck,
                                             configmanager)
        return
    nodename = get_nodename(configmanager, handler, info)
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
        discopool.spawn_n(eval_node, configmanager, handler, info, nodename)


def safe_detected(info):
    if 'hwaddr' not in info:
        return
    if info['hwaddr'] in runningevals:
        # Do not evaluate the same mac multiple times at once
        return
    runningevals[info['hwaddr']] = discopool.spawn(eval_detected, info)


def eval_detected(info):
    try:
        detected(info)
    except Exception as e:
        traceback.print_exc()
    del runningevals[info['hwaddr']]


def detected(info):
    global rechecker
    global rechecktime
    # later, manual and CMM discovery may act on SN and/or UUID
    for service in info['services']:
        if nodehandlers.get(service, None):
            if service not in known_services:
                known_services[service] = set([])
            handler = nodehandlers[service]
            info['handler'] = handler
            break
    else:  # no nodehandler, ignore for now
        return
    try:
        snum = info['attributes']['enclosure-serial-number'][0].strip()
        if snum:
            info['serialnumber'] = snum
            known_serials[info['serialnumber']] = info
    except (KeyError, IndexError):
        pass
    try:
        info['modelnumber'] = info['attributes']['enclosure-machinetype-model'][0]
        known_services[service].add(info['modelnumber'])
    except (KeyError, IndexError):
        pass
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
    handler = handler.NodeHandler(info, cfg)
    handler.scan()
    uuid = info.get('uuid', None)
    if uuid_is_valid(uuid):
        known_uuids[uuid][info['hwaddr']] = info
    if handler.https_supported and not handler.https_cert:
        if handler.cert_fail_reason == 'unreachable':
            log.log(
                {
                    'info': '{0} with hwaddr {1} is not reachable at {2}'
                            ''.format(
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
        if rechecker is None or rechecker.dead:
            rechecktime = util.monotonic_time() + 300
            rechecker = eventlet.spawn_after(300, _periodic_recheck, cfg)
        unknown_info[info['hwaddr']] = info
        info['discostatus'] = 'unidentfied'
        #TODO, eventlet spawn after to recheck sooner, or somehow else
        # influence periodic recheck to shorten delay?
        return
    nodename = get_nodename(cfg, handler, info)
    if nodename and handler.https_supported:
        dp = cfg.get_node_attributes([nodename],
                                     ('pubkeys.tls_hardwaremanager',))
        lastfp = dp.get(nodename, {}).get('pubkeys.tls_hardwaremanager',
                                          {}).get('value', None)
        if util.cert_matches(lastfp, handler.https_cert):
            info['nodename'] = nodename
            known_nodes[nodename][info['hwaddr']] = info
            info['discostatus'] = 'discovered'
            return  # already known, no need for more
    #TODO(jjohnson2): We might have to get UUID for certain searches...
    #for now defer probe until inside eval_node.  We might not have
    #a nodename without probe in the future.
    if nodename:
        eval_node(cfg, handler, info, nodename)
    else:
        log.log(
            {'info': 'Detected unknown {0} with hwaddr {1} at '
                     'address {2}'.format(
                        handler.devname, info['hwaddr'], handler.ipaddr
                      )})
        info['discostatus'] = 'unidentified'
        unknown_info[info['hwaddr']] = info


def get_nodename(cfg, handler, info):
    nodename = None
    if handler.https_supported:
        currcert = handler.https_cert
        if not currcert:
            info['discofailure'] = 'nohttps'
            return None
        currprint = util.get_fingerprint(currcert)
        nodename = nodes_by_fprint.get(currprint, None)
    if not nodename:
        curruuid = info.get('uuid', None)
        if uuid_is_valid(curruuid):
            nodename = nodes_by_uuid.get(curruuid, None)
            if nodename is None:
                _map_unique_ids()
                nodename = nodes_by_uuid.get(curruuid, None)
    if not nodename:  # as a last resort, search switch for info
        nodename, macinfo = macmap.find_nodeinfo_by_mac(info['hwaddr'], cfg)
        if (nodename and
                not handler.discoverable_by_switch(macinfo['maccount'])):
            if handler.devname == 'SMM':
                errorstr = 'Attempt to discover SMM by switch, but chained ' \
                           'topology or incorrect net attributes detected, ' \
                           'which is not compatible with switch discovery ' \
                           'of SMM, nodename would have been ' \
                           '{0}'.format(nodename)
                log.log({'error': errorstr})
                return None
    return nodename


def eval_node(cfg, handler, info, nodename, manual=False):
    try:
        handler.probe()  # unicast interrogation as possible to get more data
        # for now, we search switch only, ideally we search cmm, smm, and
        # switch concurrently
        # do some preconfig, for example, to bring a SMM online if applicable
        handler.preconfig()
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
        # search for nodes fitting our description using filters
        # lead with the most specific to have a small second pass
        nl = cfg.filter_node_attributes(
            'enclosure.bay={0}'.format(info['enclosure.bay']), nl)
        nl = list(nl)
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
        if not discover_node(cfg, handler, info, nodename, manual):
            # store it as pending, assuming blocked on enclosure
            # assurance...
            pending_nodes[nodename] = info
    else:
        # we can and did accurately discover by switch or in enclosure
        if not discover_node(cfg, handler, info, nodename, manual):
            pending_nodes[nodename] = info


def discover_node(cfg, handler, info, nodename, manual):
    known_nodes[nodename][info['hwaddr']] = info
    if info['hwaddr'] in unknown_info:
        del unknown_info[info['hwaddr']]
    info['discostatus'] = 'identified'
    dp = cfg.get_node_attributes(
        [nodename], ('discovery.policy',
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
    elif policies & set(('open', 'permissive')) or manual:
        info['nodename'] = nodename
        if info['handler'] == pxeh:
            return do_pxe_discovery(cfg, handler, info, manual, nodename, policies)
        elif manual or not util.cert_matches(lastfp, handler.https_cert):
            # only 'discover' if it is not the same as last time
            try:
                handler.config(nodename)
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
            newnodeattribs = {}
            if 'uuid' in info:
                newnodeattribs['id.uuid'] = info['uuid']
            if 'serialnumber' in info:
                newnodeattribs['id.serial'] = info['serialnumber']
            if 'modelnumber' in info:
                newnodeattribs['id.model'] = info['modelnumber']
            if handler.https_cert:
                newnodeattribs['pubkeys.tls_hardwaremanager'] = \
                    util.get_fingerprint(handler.https_cert)
            if newnodeattribs:
                cfg.set_node_attributes({nodename: newnodeattribs})
            log.log({'info': 'Discovered {0} ({1})'.format(nodename,
                                                          handler.devname)})
        info['discostatus'] = 'discovered'
        return True
    log.log({'info': 'Detected {0}, but discovery.policy is not set to a '
                     'value allowing discovery (open or permissive)'.format(
                        nodename)})
    info['discofailure'] = 'policy'
    return False


def do_pxe_discovery(cfg, handler, info, manual, nodename, policies):
    # use uuid based scheme in lieu of tls cert, ideally only
    # for stateless 'discovery' targets like pxe, where data does not
    # change
    uuidinfo = cfg.get_node_attributes(nodename, ['id.uuid', 'id.serial', 'id.model', 'net*.bootable'])
    if manual or policies & set(('open', 'pxe')):
        enrich_pxe_info(info)
        attribs = {}
        olduuid = uuidinfo.get(nodename, {}).get('id.uuid', None)
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
                attribs[newattrname] = info['hwaddr']
        if attribs:
            cfg.set_node_attributes({nodename: attribs})
    if info['uuid'] in known_pxe_uuids:
        return True
    if uuid_is_valid(info['uuid']):
        known_pxe_uuids[info['uuid']] = nodename
    log.log({'info': 'Detected {0} ({1} with mac {2})'.format(
        nodename, handler.devname, info['hwaddr'])})
    return True


attribwatcher = None
nodeaddhandler = None
needaddhandled = False


def _handle_nodelist_change(configmanager):
    global needaddhandled
    global nodeaddhandler
    _recheck_nodes((), configmanager)
    if needaddhandled:
        needaddhandled = False
        nodeaddhandler = eventlet.spawn(_handle_nodelist_change, configmanager)
    else:
        nodeaddhandler = None


def newnodes(added, deleting, configmanager):
    global attribwatcher
    global needaddhandled
    global nodeaddhandler
    configmanager.remove_watcher(attribwatcher)
    allnodes = configmanager.list_nodes()
    attribwatcher = configmanager.watch_attributes(
        allnodes, ('discovery.policy', 'net*.switch',
                   'hardwaremanagement.manager', 'net*.switchport', 'id.uuid',
                   'pubkeys.tls_hardwaremanager', 'net*.bootable'), _recheck_nodes)
    if nodeaddhandler:
        needaddhandled = True
    else:
        nodeaddhandler = eventlet.spawn(_handle_nodelist_change, configmanager)



rechecker = None
rechecktime = None
rechecklock = eventlet.semaphore.Semaphore()

def _periodic_recheck(configmanager):
    global rechecker
    global rechecktime
    rechecker = None
    try:
        _recheck_nodes((), configmanager)
    except Exception:
        traceback.print_exc()
        log.log({'error': 'Unexpected error during discovery, check debug '
                          'logs'})
    # if rechecker is set, it means that an accelerated schedule
    # for rechecker was requested in the course of recheck_nodes
    if rechecker is None:
        rechecktime = util.monotonic_time() + 900
        rechecker = eventlet.spawn_after(900, _periodic_recheck,
                                         configmanager)


def rescan():
    _map_unique_ids()
    eventlet.spawn_n(slp.active_scan, safe_detected)


def start_detection():
    global attribwatcher
    global rechecker
    _map_unique_ids()
    cfg = cfm.ConfigManager(None)
    allnodes = cfg.list_nodes()
    attribwatcher = cfg.watch_attributes(
        allnodes, ('discovery.policy', 'net*.switch',
                   'hardwaremanagement.manager', 'net*.switchport', 'id.uuid',
                   'pubkeys.tls_hardwaremanager'), _recheck_nodes)
    cfg.watch_nodecollection(newnodes)
    eventlet.spawn_n(slp.snoop, safe_detected)
    eventlet.spawn_n(pxe.snoop, safe_detected)
    if rechecker is None:
        rechecktime = util.monotonic_time() + 900
        rechecker = eventlet.spawn_after(900, _periodic_recheck, cfg)

    # eventlet.spawn_n(ssdp.snoop, safe_detected)



nodes_by_fprint = {}
nodes_by_uuid = {}
known_pxe_uuids = {}

def _map_unique_ids(nodes=None):
    global nodes_by_uuid
    global nodes_by_fprint
    nodes_by_uuid = {}
    nodes_by_fprint = {}
    # Map current known ids based on uuid and fingperprints for fast lookup
    cfg = cfm.ConfigManager(None)
    if nodes is None:
        nodes = cfg.list_nodes()
    bigmap = cfg.get_node_attributes(nodes,
                                     ('id.uuid',
                                      'pubkeys.tls_hardwaremanager'))
    uuid_by_nodes = {}
    fprint_by_nodes = {}
    for uuid in nodes_by_uuid:
        if not uuid_is_valid():
            continue
        node = nodes_by_uuid[uuid]
        if node in bigmap:
            uuid_by_nodes[node] = uuid
    for fprint in nodes_by_fprint:
        node = nodes_by_fprint[fprint]
        if node in bigmap:
            fprint_by_nodes[node] = fprint
    for node in bigmap:
        if node in uuid_by_nodes:
            del nodes_by_uuid[uuid_by_nodes[node]]
        if node in fprint_by_nodes:
            del nodes_by_fprint[fprint_by_nodes[node]]
        uuid = bigmap[node].get('id.uuid', {}).get('value', None)
        if uuid_is_valid(uuid):
            nodes_by_uuid[uuid] = node
        fprint = bigmap[node].get(
            'pubkeys.tls_hardwaremanager', {}).get('value', None)
        if fprint:
            nodes_by_fprint[fprint] = node
    for uuid in known_pxe_uuids:
        if uuid_is_valid(uuid) and uuid not in nodes_by_uuid:
            nodes_by_uuid[uuid] = known_pxe_uuids[uuid]


if __name__ == '__main__':
    start_detection()
    while True:
        eventlet.sleep(30)
