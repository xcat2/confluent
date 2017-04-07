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
#import confluent.discovery.protocols.pxe as pxe
#import confluent.discovery.protocols.ssdp as ssdp
import confluent.discovery.protocols.slp as slp
import confluent.discovery.handlers.imm as imm
import confluent.discovery.handlers.smm as smm
import confluent.discovery.handlers.xcc as xcc
import confluent.exceptions as exc
import confluent.log as log
import confluent.messages as msg
import confluent.networking.macmap as macmap
import confluent.util as util
import traceback

import eventlet
import eventlet.semaphore

nodehandlers = {
    'service:lenovo-smm': smm,
    'service:management-hardware.Lenovo:lenovo-xclarity-controller': xcc,
    'service:management-hardware.IBM:integrated-management-module2': imm,
}

servicenames = {
    'service:lenovo-smm': 'lenovo-smm',
    'service:management-hardware.Lenovo:lenovo-xclarity-controller': 'lenovo-xcc',
    'service:management-hardware.IBM:integrated-management-module2': 'lenovo-imm2',
}

servicebyname = {
    'lenovo-smm': 'service:lenovo-smm',
    'lenovo-xcc': 'service:management-hardware.Lenovo:lenovo-xclarity-controller',
    'lenovo-imm2': 'service:management-hardware.IBM:integrated-management-module2',
}
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
known_services = set([])
known_serials = {}
known_nodes = {}
unknown_info = {}
pending_nodes = {}


def enumerate_by_serial(model=None, type=None):
    type = servicebyname.get(type, None)
    for info in known_info:
        info = known_info[info]
        if 'serialnumber' not in info:
            continue
        if model and info.get('modelnumber', None) != model:
            continue
        if type and type not in info['services']:
            continue
        yield msg.ChildCollection(info['serialnumber'])


def enumerate_by_mac(model=None, type=None):
    type = servicebyname.get(type, None)
    for mac in known_info:
        info = known_info[mac]
        if 'hwaddr' not in info:
            continue
        if model and info.get('modelnumber', None) != model:
            continue
        if type and type not in info['services']:
            continue
        yield msg.ChildCollection(mac.replace(':', '-'))


def enumerate_types():
    for model in detected_services():
        yield msg.ChildCollection(model + '/')


def enumerate_models():
    for model in detected_models():
        yield msg.ChildCollection(model + '/')


disco_info = {
    'by-serial': enumerate_by_serial,
    'by-mac': enumerate_by_mac,
}

category_info = {
    'by-serial': enumerate_by_serial,
    'by-mac': enumerate_by_mac,
    'by-type': enumerate_types,
    'by-model': enumerate_models,
}

group_info = {
    'by-type': disco_info,
    'by-model': disco_info,
}


def handle_api_request(configmanager, inputdata, operation, pathcomponents):
    if len(pathcomponents) == 1:
        return [ msg.ChildCollection(x + '/') for x in category_info]
    elif len(pathcomponents) == 2:
        category = pathcomponents[1]
        if category not in category_info:
            raise exc.NotFoundException(category + ' not a valid discovery category')
        return category_info[category]()
    elif len(pathcomponents) == 3:
        if pathcomponents[1] in group_info:
            return [ msg.ChildCollection(x + '/') for x in disco_info ]
        elif pathcomponents[1] in disco_info:
            return disco_info[pathcomponents[1]]()
    elif len(pathcomponents) == 4:
        if pathcomponents[1] == 'by-model':
            return disco_info[pathcomponents[3]](model=pathcomponents[2])
        elif pathcomponents[1] == 'by-type':
            return disco_info[pathcomponents[3]](type=pathcomponents[2])
    raise exc.NotFoundException()


def detected_services():
    for srv in known_services:
        yield servicenames[srv]


def info_by_service(service):
    service = servicebyname[service]
    for mac in known_info:
        info = known_info[mac]
        if srv in info['services']:
            if srv == service:
                yield info
                break


def detected_serials():
    return iter(known_serials)


def info_by_serial(serial):
    return known_serials.get(serial, None)


def detected_models():
    knownmodels = set([])
    for info in known_info:
        info = known_info[info]
        if 'modelnumber' in info and info['modelnumber'] not in knownmodels:
            knownmodels.add(info['modelnumber'])
            yield info['modelnumber']


def info_by_model(model):
    for info in known_info:
        info = known_info[info]
        if 'modelnumber' in info and info['modelnumber'] == model:
            yield info


def _recheck_nodes(nodeattribs, configmanager):
    global rechecker
    _map_unique_ids(nodeattribs)
    # for the nodes whose attributes have changed, consider them as potential
    # strangers
    for node in nodeattribs:
        if node in known_nodes:
            unknown_info[known_nodes[node]['hwaddr']] = known_nodes[node]
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
        handler = info['handler'].NodeHandler(info, configmanager)
        eventlet.spawn_n(eval_node, configmanager, handler, info, nodename)


def _recheck_single_unknown(configmanager, mac):
    global rechecker
    info = unknown_info.get(mac, None)
    if not info:
        return
    if not info.get('addresses', None):
        log.log({'info': 'Missing address information in ' + repr(info)})
        return
    handler = info['handler'].NodeHandler(info, configmanager)
    if not handler.https_cert:
        if handler.cert_fail_reason == 'unreachable':
            log.log(
                {
                    'info': '{0} with hwaddr {1} is not reachable at {2}'
                            ''.format(
                        handler.devname, info['hwaddr'], handler.ipaddr
                    )})
            # addresses data is bad, clear it, to force repair next
            # opportunity
            info['addresses'] = []
            # TODO(jjohnson2):  rescan due to bad peer addr data?
            # not just wait around for the next announce
            return
        log.log(
            {
                'info': '{0} with hwaddr {1} at address {2} is not yet running '
                        'https, will examine later'.format(
                    handler.devname, info['hwaddr'], handler.ipaddr
                )})
        if rechecker is not None:
            rechecker.cancel()
        # if cancel did not result in dead, then we are in progress
        if rechecker is None or rechecker.dead:
            rechecker = eventlet.spawn_after(60, _periodic_recheck,
                                             configmanager)
        return
    nodename = get_nodename(configmanager, handler, info)
    if nodename:
        eventlet.spawn_n(eval_node, configmanager, handler, info, nodename)


def safe_detected(info):
    eventlet.spawn_n(eval_detected, info)


def eval_detected(info):
    try:
        return detected(info)
    except Exception as e:
        traceback.print_exc()


def detected(info):
    global rechecker
    if 'hwaddr' not in info:
        return  # For now, require hwaddr field to proceed
    # later, manual and CMM discovery may act on SN and/or UUID
    for service in info['services']:
        if nodehandlers.get(service, None):
            known_services.add(service)
            handler = nodehandlers[service]
            info['handler'] = handler
            break
    else:  # no nodehandler, ignore for now
        return
    try:
        snum = info['attributes']['enclosure-serial-number'][0].rstrip()
        if snum:
            info['serialnumber'] = snum
            known_serials[info['serialnumber']] = info
    except (KeyError, IndexError):
        pass
    try:
        info['modelnumber'] = info['attributes']['enclosure-machinetype-model'][0]
    except (KeyError, IndexError):
        pass
    if info['hwaddr'] in known_info:
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
        oldaddr = known_info[info['hwaddr']]['addresses']
        for addr in info['addresses']:
            if addr[0].startswith('fe80::'):
                break
        else:
            for addr in oldaddr:
                if addr[0].startswith('fe80::'):
                    info['addresses'].append(addr)
        if known_info[info['hwaddr']]['addresses'] == info['addresses']:
            # if the ip addresses match, then assume no changes
            # now something resetting to defaults could, in theory
            # have the same address, but need to be reset
            # in that case, however, a user can clear pubkeys to force a check
            return
    known_info[info['hwaddr']] = info
    cfg = cfm.ConfigManager(None)
    handler = handler.NodeHandler(info, cfg)
    if not handler.https_cert:
        if handler.cert_fail_reason == 'unreachable':
            log.log(
                {
                    'info': '{0} with hwaddr {1} is not reachable at {2}'
                            ''.format(
                        handler.devname, info['hwaddr'], handler.ipaddr
                    )})
            info['addresses'] = []
            return
        log.log(
            {'info':  '{0} with hwaddr {1} at address {2} is not yet running '
                      'https, will examine later'.format(
                        handler.devname, info['hwaddr'], handler.ipaddr
            )})
        if rechecker is not None:
            rechecker.cancel()
        if rechecker is None or rechecker.dead:
            rechecker = eventlet.spawn_after(60, _periodic_recheck, cfg)
        unknown_info[info['hwaddr']] = info
        #TODO, eventlet spawn after to recheck sooner, or somehow else
        # influence periodic recheck to shorten delay?
        return
    nodename = get_nodename(cfg, handler, info)
    if nodename:
        dp = cfg.get_node_attributes([nodename],
                                     ('pubkeys.tls_hardwaremanager',))
        lastfp = dp.get(nodename, {}).get('pubkeys.tls_hardwaremanager',
                                          {}).get('value', None)
        if util.cert_matches(lastfp, handler.https_cert):
            info['nodename'] = nodename
            known_nodes[nodename] = info
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
        unknown_info[info['hwaddr']] = info


def get_nodename(cfg, handler, info):
    currcert = handler.https_cert
    if not currcert:
        info['discofailure'] = 'nohttps'
        return None
    currprint = util.get_fingerprint(currcert)
    nodename = nodes_by_fprint.get(currprint, None)
    # TODO, opportunistically check uuid if not nodename
    if not nodename:
        nodename = macmap.find_node_by_mac(info['hwaddr'], cfg)
    return nodename


def eval_node(cfg, handler, info, nodename):
    try:
        handler.probe()  # unicast interrogation as possible to get more data
        # for now, we search switch only, ideally we search cmm, smm, and
        # switch concurrently
    except Exception as e:
        unknown_info[info['hwaddr']] = info
        log.log({'error': 'An error occured during discovery, check the '
                          'trace and stderr logs, mac was {0} and ip was {1}'
                          ', the node or the containing enclosure was {2}'
                          ''.format(info['hwaddr'], handler.ipaddr,
                                    nodename)})
        traceback.print_exc()
        return
    # do some preconfig, for example, to bring a SMM online if applicable
    handler.preconfig()
    # first, if had a bay, it was in an enclosure.  If it was discovered by
    # switch, it is probably the enclosure manager and not
    # the node directly.  switch is ambiguous and we should leave it alone
    if 'enclosure.bay' in info and handler.is_enclosure:
        unknown_info[info['hwaddr']] = info
        log.log({'error': 'Something that is an enclosure reported a bay, '
                          'not possible'})
        return
    nl = list(cfg.filter_node_attributes('enclosure.manager=' + nodename))
    if not handler.is_enclosure and nl:
        # The specified node is an enclosure (has nodes mapped to it), but
        # what we are talking to is *not* an enclosure
        if 'enclosure.bay' not in info:
            unknown_info[info['hwaddr']] = info
            log.log({'error': '{2} with mac {0} is in {1}, but unable to '
                              'determine bay number'.format(info['hwaddr'],
                                                            nodename,
                                                            handler.ipaddr)})
            return
        # search for nodes fitting our description using filters
        # lead with the most specific to have a small second pass
        nl = cfg.filter_node_attributes(
            'enclosure.bay=' + info['enclosure.bay'], nl)
        nl = list(nl)
        if len(nl) != 1:
            info['discofailure'] = 'ambigconfig'
            if len(nl):
                log.log({'error': 'The following nodes have duplicate '
                                  'enclosure attributes: ' + ','.join(nl)})
            else:
                log.log({'error': 'The {0} in enclosure {1} bay {2} does not '
                                  'seem to be a defined node ({3})'.format(
                                        handler.devname, nodename,
                                        info['enclosure.bay'],
                                        handler.ipaddr,
                                    )})
            unknown_info[info['hwaddr']] = info
            return
        nodename = nl[0]
        if not discover_node(cfg, handler, info, nodename):
            # store it as pending, assuming blocked on enclosure
            # assurance...
            pending_nodes[nodename] = info
    else:
        # we can and did accurately discover by switch or in enclosure
        if not discover_node(cfg, handler, info, nodename):
            pending_nodes[nodename] = info


def discover_node(cfg, handler, info, nodename):
    if info['hwaddr'] in unknown_info:
        del unknown_info[info['hwaddr']]
    dp = cfg.get_node_attributes(
        [nodename], ('discovery.policy',
                     'pubkeys.tls_hardwaremanager'))
    policy = dp.get(nodename, {}).get('discovery.policy', {}).get(
        'value', None)
    lastfp = dp.get(nodename, {}).get('pubkeys.tls_hardwaremanager',
                                      {}).get('value', None)
    # TODO(jjohnson2): permissive requires we guarantee storage of
    # the pubkeys, which is deferred for a little bit
    # Also, 'secure', when we have the needed infrastructure done
    # in some product or another.
    if policy == 'permissive' and lastfp:
        info['discofailure'] = 'fingerprint'
        log.log({'info': 'Detected replacement of {0} with existing '
                         'fingerprint and permissive discovery policy, not '
                         'doing discovery unless discovery.policy=open or '
                         'pubkeys.tls_hardwaremanager attribute is cleared '
                         'first'.format(nodename)})
        return False  # With a permissive policy, do not discover new
    elif policy in ('open', 'permissive'):
        if not util.cert_matches(lastfp, handler.https_cert):
            if info['hwaddr'] in unknown_info:
                del unknown_info[info['hwaddr']]
            handler.config(nodename)
            newnodeattribs = {}
            if 'uuid' in info:
                newnodeattribs['id.uuid'] = info['uuid']
            if handler.https_cert:
                newnodeattribs['pubkeys.tls_hardwaremanager'] = \
                    util.get_fingerprint(handler.https_cert)
            if newnodeattribs:
                cfg.set_node_attributes({nodename: newnodeattribs})
            log.log({'info': 'Discovered {0}'.format(nodename)})
        info['nodename'] = nodename
        known_nodes[nodename] = info
        return True
    log.log({'info': 'Detected {0}, but discovery.policy is not set to a '
                     'value allowing discovery (open or permissive)'.format(
                        nodename)})
    info['discofailure'] = 'policy'
    return False


attribwatcher = None


def newnodes(added, deleting, configmanager):
    global attribwatcher
    configmanager.remove_watcher(attribwatcher)
    allnodes = configmanager.list_nodes()
    attribwatcher = configmanager.watch_attributes(
        allnodes, ('discovery.policy', 'net.switch',
                   'hardwaremanagement.manager', 'net.switchport', 'id.uuid',
                   'pubkeys.tls_hardwaremanager'), _recheck_nodes)
    _recheck_nodes((), configmanager)


rechecker = None
rechecklock = eventlet.semaphore.Semaphore()

def _periodic_recheck(configmanager):
    global rechecker
    rechecker = None
    # There shouldn't be anything causing this to double up, but just in case
    # use a semaphore to absolutely guarantee this doesn't multiply
    with rechecklock:
        try:
            _recheck_nodes((), configmanager)
        except Exception:
            traceback.print_exc()
            log.log({'error': 'Unexpected error during discovery, check debug '
                              'logs'})
    # if rechecker is set, it means that an accelerated schedule
    # for rechecker was requested in the course of recheck_nodes
    if rechecker is None:
        rechecker = eventlet.spawn_after(900, _periodic_recheck,
                                         configmanager)


def start_detection():
    global attribwatcher
    global rechecker
    _map_unique_ids()
    cfg = cfm.ConfigManager(None)
    allnodes = cfg.list_nodes()
    attribwatcher = cfg.watch_attributes(
        allnodes, ('discovery.policy', 'net.switch',
                   'hardwaremanagement.manager', 'net.switchport', 'id.uuid',
                   'pubkeys.tls_hardwaremanager'), _recheck_nodes)
    cfg.watch_nodecollection(newnodes)
    eventlet.spawn_n(slp.snoop, safe_detected)
    if rechecker is None:
        rechecker = eventlet.spawn_after(900, _periodic_recheck, cfg)
    # eventlet.spawn_n(ssdp.snoop, safe_detected)
    # eventlet.spawn_n(pxe.snoop, safe_detected)


nodes_by_fprint = {}
nodes_by_uuid = {}

def _map_unique_ids(nodes=None):
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
        node = nodes_by_uuid[uuid]
        if node in bigmap:
            uuid_by_nodes[node] = uuid
    for fprint in nodes_by_fprint:
        node = nodes_by_fprint[fprint]
        if node in bigmap:
            fprint_by_nodes[node] =fprint
    for node in bigmap:
        if node in uuid_by_nodes:
            del nodes_by_uuid[uuid_by_nodes[node]]
        if node in fprint_by_nodes:
            del nodes_by_fprint[fprint_by_nodes[node]]
        uuid = bigmap[node].get('id.uuid', {}).get('value', None)
        if uuid:
            nodes_by_uuid[uuid] = node
        fprint = bigmap[node].get(
            'pubkeys.tls_hardwaremanager', {}).get('value', None)
        if fprint:
            nodes_by_fprint[fprint] = node


if __name__ == '__main__':
    start_detection()
    while True:
        eventlet.sleep(30)