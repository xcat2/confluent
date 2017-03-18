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
import confluent.discovery.handlers.xcc as xcc
import confluent.discovery.handlers.smm as smm
import confluent.log as log
import confluent.networking.macmap as macmap
import confluent.util as util
import traceback

import eventlet

nodehandlers = {
    'service:lenovo-smm': smm,
    'service:management-hardware.Lenovo:lenovo-xclarity-controller': xcc,
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


def add_validated_fingerprint(nodename, fingerprint, role='manager'):
    """Add a physically validated certificate fingerprint

    When a secure validater validates a fingerprint, this function is used to
    mark that fingerprint as validated.
    """
    pass


class DiscoveredNode(object):

    def __init__(self, uuid, serial=None, hwaddr=None, model=None,
                 modelnumber=None):
        """A representation of a discovered node

        This provides a representation of a discovered, but not yet located
        node.  The goal is to be given enough unique identifiers to help
        automatic and manual selection have information to find it.

        :param uuid: The UUID as it would appear in DMI table of the node
                     other UUIDs may appear, but a node is expected to be held
                     together by this UUID, and ideally would appear in PXE
                     packets.  For certain systems (e.g. enclosure managers),
                     this may be some other UUID if DMI table does not apply.
        :param serial:  Vendor assigned serial number for the node, if available
        :param hwaddr:  A primary MAC address that may be used for purposes of
                        locating the node.  For example mac address that is used
                        to search ethernet switches.
        :param model: A human readable description of the model.
        :param modelnumber:  If applicable, a numeric representation of the
                            model.

        """
        self.uuid = uuid
        self.serial = serial
        # self.netinfo = netinfo
        self.fingerprints = {}
        self.model = model
        self.modelnumber = modelnumber

    def add_fingerprint(self, type, hashalgo, fingerprint):
        """Add a fingerprint to a discovered node

        Provide either an in-band certificate or manager certificate

        :param type: Indicates whether the certificate is a system or manager
                     certificate
        :param hashalgo: The algorithm used to generate fingerprint (SHA256,
                         SHA512)
        :param fingerprint: The signgature of the public certificate
        :return:
        """
        self.fingerprints[type] = (hashalgo, fingerprint)


    def identify(self, nodename):
        """Have discovered node check and auto add if appropriate

        After discovery examines a system, location plugins or client action
        may promote a system.  This is the function that handles promotion of
        a 'discovered' system to a full-fledged node.

        :param nodename: The node name to associate with this node
        :return:
        """
        # Ok, so at this point we want to pull in data about a node, and
        # attribute data may flow in one of a few ways depending on things:
        # If the newly defined node *would* have a hardwaremanagement.method
        # defined, then use that.  Otherwise, the node should suggest
        # it's own.  If it doesn't then we use the 'ipmi' default.
        # If it has a password explictly to use from user, use that.  Otherwise
        # generate a random password unique to the end point and set
        # that per-node.
        # If the would-be node has a defined hardwaremanagement.manager
        # and that defined value is *not* fe80, reprogram the BMC
        # to have that value.  Otherwise, if possible, take the current
        # fe80 and store that as hardwaremanagement.manager
        # If no fe80 possible *and* no existing value, error and do nothing
        # if security policy not set, this should only proceed if fingerprint
        # is validated by a secure validator.
        pass

#TODO: by serial, by uuid, by node
known_info = {}
known_nodes = {}
unknown_info = {}
pending_nodes = {}


def _recheck_nodes(nodeattribs, configmanager):
    # First we go through ones we did not find earlier
    _map_unique_ids(nodeattribs)
    for node in nodeattribs:
        if node in known_nodes:
            unknown_info[known_nodes[node]['hwaddr']] = known_nodes[node]
    for mac in list(unknown_info):
        info = unknown_info.get(mac, None)
        if not info:
            continue
        handler = info['handler'].NodeHandler(info, configmanager)
        nodename = get_nodename(configmanager, handler, info)
        if nodename:
            eventlet.spawn_n(eval_node, configmanager, handler, info, nodename)
    # now we go through ones that were identified, but could not pass
    # policy or hadn't been able to verify key
    for nodename in pending_nodes:
        info = pending_nodes[nodename]
        handler = info['handler'].NodeHandler(info, configmanager)
        eventlet.spawn_n(eval_node, configmanager, handler, info, nodename)
    # TODO(jjohnson2): Need to also go over previously discovered to see
    # if configuration matches reality, so examine known_info to verify match
    # avoiding probe and preconfig to avoid running afoul of security
    # detection

def safe_detected(info):
    eventlet.spawn_n(eval_detected, info)


def eval_detected(info):
    try:
        return detected(info)
    except Exception as e:
        traceback.print_exc()


def detected(info):
    for service in info['services']:
        if nodehandlers.get(service, None):
            handler = nodehandlers[service]
            info['handler'] = handler
            break
    else:  # no nodehandler, ignore for now
        return
    if 'hwaddr' not in info:
        return  # For now, require hwaddr field to proceed
        # later, manual and CMM discovery may act on SN and/or UUID
    if info['hwaddr'] in known_info:
        # we should tee these up for parsing when an enclosure comes up
        # also when switch config parameters change, should discard
        # and there's also if wiring is fixed...
        # of course could periodically revisit known_nodes
        return
    known_info[info['hwaddr']] = info
    cfg = cfm.ConfigManager(None)
    handler = handler.NodeHandler(info, cfg)
    # TODO: first check by filter_attributes for uuid match...
    # but maybe not..... since UUID uniqueness is a challenge...
    # but could search by cert fingerprint....
    nodename = get_nodename(cfg, handler, info)
    if nodename:
        dp = cfg.get_node_attributes([nodename],
                                     ('pubkeys.tls_hardwaremanager'))
        lastfp = dp.get(nodename, {}).get('pubkeys.tls_hardwaremanager',
                                          {}).get('value', None)
        if util.cert_matches(lastfp, handler.https_cert):
            return  # already known, no need for more
    try:
        handler.probe()  # unicast interrogation as possible to get more data
        # for now, we search switch only, ideally we search cmm, smm, and
        # switch concurrently
    except Exception as e:
        traceback.print_exc()
        return
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
    # do some preconfig, for example, to bring a SMM online if applicable
    handler.preconfig()
    # first, if had a bay, it was in an enclosure.  If it was discovered by
    # switch, it is probably the enclosure manager and not
    # the node directly.  switch is ambiguous and we should leave it alone
    if 'enclosure.bay' in info:
        myenclosure = \
            cfg.get_node_attributes(nodename, ('enclosure.manager',))
        myenclosure = myenclosure.get(nodename, {}).get(
            'enclosure.manager', {}).get('value', None)
        if myenclosure:  # Discovery mechanism was specific
            if not discover_node(cfg, handler, info, nodename):
                pending_nodes[nodename] = info
            return
        # we have an enclosure, but we are not defined to be in an
        # enclosure, so go ahead and assume that we are misidentified
        # as our enclosure manager
        # search for nodes fitting our description using filters
        # lead with the most specific to have a small second pass
        nl = cfg.filter_node_attributes('enclosure.manager=' + nodename)
        nl = cfg.filter_node_attributes(
            'enclosure.bay=' + info['enclosure.bay'], nl)
        nl = [x for x in nl]  # listify for sake of len
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
        # we can and did discover by switch
        if not discover_node(cfg, handler, info, nodename):
            pending_nodes[nodename] = info


def discover_node(cfg, handler, info, nodename):
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
        known_nodes[nodename] = info
        log.log({'info': 'Discovered {0}'.format(nodename)})
        return True
    log.log({'info': 'Detected {0}, but discovery.policy is not set to a '
                     'value allowing discovery (open or permmissive)'.format(
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


def _periodic_recheck(configmanager):
    while True:
        eventlet.sleep(900)
        _recheck_nodes((), configmanager)


def start_detection():
    global attribwatcher
    _map_unique_ids()
    cfg = cfm.ConfigManager(None)
    allnodes = cfg.list_nodes()
    attribwatcher = cfg.watch_attributes(
        allnodes, ('discovery.policy', 'net.switch',
                   'hardwaremanagement.manager', 'net.switchport', 'id.uuid',
                   'pubkeys.tls_hardwaremanager'), _recheck_nodes)
    cfg.watch_nodecollection(newnodes)
    eventlet.spawn_n(slp.snoop, safe_detected)
    eventlet.spawn_n(_periodic_recheck, cfg)
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