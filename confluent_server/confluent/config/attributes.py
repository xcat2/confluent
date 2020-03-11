# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
# Copyright 2015-2019 Lenovo
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


#This defines the attributes of various classes of things

# 'nic', meant to be a nested structure under node
# changing mind on design, flattening to a single attribute, a *touch* less
# flexible at the top end, but much easier on the low end
# now net.<name>.attribute scheme
# similarly, leaning toward comma delimited ip addresses, since 99.99% of the
# time each nic will have one ip address
# vlan specification will need to be thought about a tad, each ip could be on
# a distinct vlan, but could have a vlan without an ip for sake of putting
# to a bridge.  Current thought is
# vlans attribute would be comma delimited referring to the same index
# as addresses, with either 'native' or a number for vlan id
# the 'joinbridge' attribute would have some syntax like @<vlanid> to indicate
# joining only a vlan of the nic to the bridge
# 'joinbond' attribute would not support vlans.

#nic = {
#    'name': {
#        'description': 'Name in ip/ifconfig as desired by administrator',
#    },
#    'biosdevname': {
#        'description': '"biosdevname" scheme to identify the adapter. If not'
#                       'mac address match is preferred, then biosdevname, then'
#                       'name.',
#    },
#    'port': {
#        'description': 'Port that this nic connects to',
#    },
#    'switch': {
#        'description': 'Switch that this nic connects to',
#    },
#    'customhardwareaddress': {
#        'description': 'Mac address to push to nic',
#    },
#    'dnssuffix': {
#        'description': ('String to place after nodename, but before'
#                        'Network.Domain to derive FQDN for this NIC'),
#    },
#    'hardwareaddress': {
#        'description': 'Active mac address on this nic (factory or custom)'
#    },
#    'ipaddresses': {
#        'description': 'Set of IPv4 and IPv6 addresses in CIDR format'
#    },
#    'pvid': {
#        'description': 'PVID of port on switch this nic connects to',
#    },
#    'mtu': {
#        'description': 'Requested MTU to configure on this interface',
#    },
#    'vlans': {
#        'description': 'Tagged VLANs to apply to nic/switch',
#    },
#    'dhcpv4enabled': {
#        'description':  ('Whether DHCP should be attempted to acquire IPv4'
#                         'address on this interface'),
#    },
#    'dhcpv6enabled': {
#        'description':  ('Whether DHCP should be attempted to acquire IPv6'
#                         'address on this interface'),
#    },
#}

user = {
    'password': {
        'description':  'The passphrase used to authenticate this user'
    },
}

# 'node', which can be considered a 'system' or a 'vm'
node = {
    'groups': {
        'type': list,
        'description': ('List of static groups for which this node is '
                        'considered a member'),
    },
    'type': {
        'description': ('Classification of node as server or switch'),
        'validvalues': ('switch', 'server'),
    },
    'api.key': {
        'description': ('Crypt of api key for self api requests by node'),
    },
    'api.armed': {
        'description': ('Indicates whether the node authentication token interface '
                        'is armed.  If set to once, it will grant only the next '
                        'request. If set to continuous, will allow many requests.'
                        'Should not be set unless an OS deployment is pending.'),
    },
    #'id': {
    #    'description': ('Numeric identifier for node')
    #},
    # autonode is the feature of generating nodes based on connectivity to
    # current node.  In recursive autonode, for now we just allow endpoint to
    # either be a server directly *or* a server enclosure.  This precludes
    # for the moment a concept of nested arbitrarily deep, but for now do this.
    # hypothetically, one could imagine supporting an array and 'popping'
    # names until reaching end.  Not worth implementing at this point.  If
    # a traditional switch is added, it needs some care and feeding anyway.
    # If a more exciting scheme presents itself, well we won't have to
#   # own discovering switches anyway.
#   'autonode.servername': {
#       'description': ('Template for creating nodenames for automatic '
#                       'creation of nodes detected as children of '
#                       'this node.  For example, a node in a server '
#                       'enclosure bay or a server connected to a switch or '
#                       'an enclosure manager connected to a switch.  Certain '
#                       'special template parameters are available and can '
#                       'be used alongside usual config template directives. '
#                       '"discovered.nodenumber" will be replaced with the '
#                       'bay or port number where the child node is connected.'
#                       ),
#   },
#   'autonode.servergroups': {
#       'type': list,
#       'description': ('A list of groups to which discovered nodes will '
#                       'belong to.  As in autonode.servername, "discovered." '
#                       'variable names will be substituted in special context')
#   },
#   'autonode.enclosurename': {
#       'description': ('Template for creating nodenames when the discovered '
#                       'node is an enclosure that will in turn generate nodes.'
#                       )
#   },
#   'autonode.enclosuregroups': {
#       'type': list,
#       'description': ('A list of groups to which a discovered node will be'
#                       'placed, presuming that node is an enclosure.')
#   },
#For now, we consider this eventuality if needed.  For now emphasize paradigm
# of group membership and see how far that goes.
#    'autonode.copyattribs': {
#        'type': list,
#        'description': ('A list of attributes to copy from the node generator '
#                        'to the generated node.  Expressions will be copied '
#                        'over without evaluation, so will be evaluated '
#                        'in the context of the generated node, rather than the'
#                        'parent node.  By default, an enclosure will copy over'
#                        'autonode.servername, so that would not need to be '
#                        'copied ')
#    },
    'collective.manager': {
        'description': ('When in collective mode, the member of the '
                        'collective currently considered to be responsible '
                        'for this node.  At a future date, this may be '
                        'modified automatically if another attribute '
                        'indicates candidate managers, either for '
                        'high availability or load balancing purposes.')
    },
    'deployment.pendingprofile': {
        'description': ('An OS profile that is pending deployment.  This indicates to '
                        'the network boot subsystem what should be offered when a potential '
                        'network boot request comes in')
    },
    'deployment.useinsecureprotocols': {
        'description': ('What phase(s) of boot are permitted to use insecure protocols '
                        '(TFTP and HTTP without TLS.  By default, HTTPS is allowed.  However '
                        'this is not compatible with most firmware in most scenarios.  Using '
                        '"firmware" as the setting will still use HTTPS after the initial download, '
                        'though be aware that a successful compromise during the firmware phase '
                        'will negate future TLS protections.  The value "always" will result in '
                        'tftp/http being used for entire deployment.  Note that ONIE does not '
                        'support secure protocols, and in that case this setting must be "always" '
                        'or "firmware"'),
        'validlist': ('always', 'firmware', 'never'),
    },
    'discovery.passwordrules': {
        'description':  'Any specified rules shall be configured on the BMC '
                        'upon discovery.  "expiration=no,loginfailures=no,complexity=no,reuse=no" '
                        'would disable password expiration, login failures '
                        'triggering a lockout, password complexity requirements,'
                        'and any restrictions around reusing an old password.',
        'validlistkeys': ('expiration', 'loginfailures', 'complexity', 'reuse'),
    },
    'discovery.policy': {
        'description':  'Policy to use for auto-configuration of discovered '
                        'and identified nodes. Valid values are "manual", '
                        '"permissive", or "open". "manual" means nodes are '
                        'detected, but not autoconfigured until a user '
                        'approves. "permissive" indicates to allow discovery, '
                        'so long as the node has no existing public key. '
                        '"open" allows discovery even if a known public key '
                        'is already stored',
        'validlist': ('manual', 'permissive', 'pxe', 'open'),
    },
    'info.note': {
        'description':  'A field used for administrators to make arbitrary '
                        'notations about nodes. This is meant entirely for '
                        'human use and not programmatic use, so it can be '
                        'freeform text data without concern for issues in how '
                        'the server will process it.',
    },
    'location.height': {
        'description': 'Height in RU of the system (defaults to query the systems)',
    },
    'location.room': {
        'description': 'Room description for the node',
    },
    'location.row': {
        'description': 'Row description for the rack the node is in',
    },
    'location.rack': {
        'description': 'Rack number of the rack the node is in',
    },
    'location.u': {
        'description': 'Position in the rack of the node',
    },
#    'location.timezone': {
#        'description': 'POSIX timezone to apply to this node',
#    },
#    'status.summary': {
#        'description': ('An assessment of the overall health of the node.  It'
#                        'can be "optimal", "warning", "critical"'),
#    },
#    'status.lastheartbeat': {
#        'description': 'Timestamp of last received heartbeat',
#    },
#    'status.heartbeatexpiry': {
#        'description': 'Time when Heartbeat will be considered expired',
#    },
#    'status.deployment': {
#        'description': 'State of any deployment activity in progress',
#    },
#    'status.faultdetails': {
#        'description': 'Detailed problem data, if any',
#    },
#    'network.gateway': {
#        'description': 'Default gateway to configure node with',
#    },
#    'network.nameservers': {
#        'description': '''DNS servers for node to use''',
#    },
#    'network.domain': {
#        'description': 'Value to append to nodename, if any, to get FQDN',
#    },
#    'network.interfaces': {
#        'dictof': 'nic',
#        'description': ('Dict of network interfaces to configure on node. '
#                       'Keyed on hardware address.'),
#    },
#    'storage.osvolume': {
#        'default': 'auto',
#        'description': 'Description of storage to target when deploying OS',
#    },
#    'storage.clientiqn': {
#        'description': ('Indicates IQN used by this node when communicating'
#                        'with iSCSI servers'),
#    },
#    'storage.iscsiserver': {
#        'description': 'Address of iSCSI server used for boot if applicable',
#    },
#    'storage.pool': {
#        'description': ('For scenarios like SAN boot and virtualization, this'
#                        'describes the pool to allocate boot volume from'),
#    },
#    'os.imagename': {
#        'description': 'The OS Image applied or to be applied to node',
#    },
#    'console.speed': {
#        'default': 'auto',
#        'description': ('Indicate the speed at which to run serial port.'
#                        'Default behavior is to autodetect the appropriate'
#                        'value as possible')
#    },
#    'console.port': {
#        'default': 'auto',
#        'description': ('Indicate which port to use for text console. '
#                        'Default behavior is to auto detect the value '
#                        'appropriate for the platform.  "Disable" can be used
#                        'to suppress serial console configuration')
#    },
    'console.logging': {
        'description': ('Indicate logging level to apply to console.  Valid '
                        'values are currently "full", "interactive", and '
                        '"none". Defaults to "full".'),
        'validvalues': ('full', 'interactive', 'none'),
    },
    'console.method': {
        'description': ('Indicate the method used to access the console of '
                        'the managed node.'),
        'validvalues': ('ssh', 'ipmi', 'tsmsol'),
    },
#    'virtualization.host': {
#        'description': ('Hypervisor where this node does/should reside'),
#        'appliesto': ['vm'],
#    },
#    'virtualization.computepool': {
#        'description': ('Set of compute resources this node is permitted to'
#                        ' be created on/be migrated to'),
#        'appliesto': ['vm'],
#    },
#    'virtualization.storagemodel': {
#        'description': ('The model of storage adapter to emulate in a virtual'
#                        'machine.  Defaults to virtio-blk for KVM, vmscsi for'
#                        'VMware'),
#        'appliesto': ['vm'],
#    },
#    'virtualization.nicmodel': {
#        'description': ('The model of NIC adapter to emulate in a virtual'
#                        'machine.  Defaults to virtio-net for KVM, vmxnet3 '
#                        'for VMware'),
#        'appliesto': ['vm'],
#    },
    'hardwaremanagement.manager': {
        'description': 'The management address dedicated to this node.  This '
                       'is the address of, for example, the Lenovo IMM.',
    },
    'hardwaremanagement.method': {
        'description': 'The method used to perform operations such as power '
                       'control, get sensor data, get inventory, and so on. '
    },
    'enclosure.bay': {
         'description': 'The bay in the enclosure, if any',
#        'appliesto': ['system'],
    },
    'enclosure.extends': {
        'description': 'When using an extendable enclosure, this is the node '
                       'representing the manager that is one closer to the '
                       'uplink.',
    },
    'enclosure.manager': {
        'description': "The management device for this node's chassis",
#        'appliesto': ['system'],
    },

#    'enclosure.type': {
#        'description': '''The type of enclosure in use (e.g. IBM BladeCenter,
#IBM Flex)''',
#        'appliesto': ['system'],
#    },
    'id.model': {
        'description': 'The model number of a node.  In scenarios where there '
                       'is both a name and a model number, it is generally '
                       'expected that this would be the generally more '
                       'specific model number.'
    },
    'id.serial': {
        'description': 'The manufacturer serial number of node',
    },
    'id.uuid': {
        'description': 'The UUID of the node as presented in DMI.',
    },
    # For single interface mac collection, net.bootable suffices
    # For multiple interface mac collection, we perhaps add an address field and use subnet affinity as a clue
    # to disambiguate multiple addresses for external provisioning
    # For internal provisioning, the UUID matters rather than the MAC, though subnet affinity may
    # still be a factor to select the appropriate static config to send down.  In such a case bonding
    # is hopefully more likely as that's a bit easier.
    # Start with the first case and only document that, the other thoughts can be future items if they turn up
    'net.bootable': {
        'type': bool,
        'description': 'Whether or not the indicated network interface is to be used for booting.  This is used by '
                       'the discovery process to decide where to place the mac address of a detected PXE nic.',
    },
    'net.ipv4_gateway': {
        'description':  'The IPv4 gateway to use if applicable.  As is the '
                        'case for other net attributes, net.eth0.ipv4_gateway '
                        'and similar is accepted.'
    },
    'net.hwaddr': {
        'description': 'The hardware address, aka MAC address of the interface indicated, generally populated by the '
                       'PXE discovery mechanism'
    },
    # 'net.pxe': { 'description': 'Whether pxe will be used on this interface'
    # TODO(jjohnson2):  Above being 'true' will control whether mac addresses
    # are stored in this nics attribute on pxe-client discovery, since
    # pxe discovery is ambiguous for BMC and system on same subnet,
    # or even both on the same port and same subnet
    'net.switch': {
        'description': 'An ethernet switch the node is connected to.  Note '
                       'that net.* attributes may be indexed by interface. '
                       'For example instead of using net.switch, it is '
                       'possible to use net.eth0.switch and net.eth1.switch '
                       'or net.0.switch and net.1.switch to define multiple '
                       'sets of net connectivity associated with each other.'
    },
    'net.switchport': {
        'description': 'The port on the switch that corresponds to this node. '
                       'See information on net.switch for more on the '
                       'flexibility of net.* attributes.'
    },
#    'id.modelnumber': {
#        'description': 'The manufacturer dictated  model number for the node',
#    },
#    'id.modelname': {
#        'description': 'The manufacturer model label for the node',
#    },
#    'id.snmpengineid': {
#        'description': 'The SNMP Engine id used by this node',
#    },
#    'secret.snmpuser': {
#        'description': 'The user to use for SNMPv3 access to this node',
#    },
#    'secret.snmppassword': {
#        'description': 'The password to use for SNMPv3 access to this node',
#    },
    'secret.snmpcommunity': {
        'description': ('SNMPv1 community string, it is highly recommended to'
                        'step up to SNMPv3'),
    },
#    'secret.snmplocalizedkey': {
#        'description': ("SNMPv3 key localized to this node's SNMP Engine id"
#                        'This can be used in lieu of snmppassphrase to avoid'
#                        'retaining the passphrase TODO: document procedure'
#                        'to commit passphrase to localized key'),
#    },
#    'secret.adminpassword': {
#        'description': ('The passphrase to apply to local root/administrator '
#                        'account. '
#                        'If the environment is 100% Linux, the value may be '
#                        'one-way crypted as in /etc/shadow.  For Windows, if '
#                        'the value is not set or is one-way crypted, the '
#                        'local '
#                        'Administrator account will be disabled, requiring '
#                        'AD')
#    },
    'secret.ipmikg': {
        'description': 'Optional Integrity key for IPMI communication.  This '
                       'should generally be ignored, as mutual authentication '
                       'is normally done with the password alone (which is a '
                       'shared secret in IPMI)'
    },
    'secret.hardwaremanagementuser': {
        'description': ('The username to use when connecting to the hardware '
                        'manager'),
    },
    'secret.hardwaremanagementpassword': {
        'description': ('Password to use when connecting to the hardware '
                        'manager'),
    },
    'pubkeys.addpolicy': {
        'description': ('Policy to use when encountering unknown public '
                        'keys.  Choices are "automatic" to accept and '
                        'store new key if no key known and "manual" '
                        'to always reject a new key, even if no key known'
                        'Note that if the trusted CA verifies the certificate,'
                        ' that is accepted ignoring this policy.  Default '
                        'policy is "automatic"'),
        'valid_values': ('automatic', 'manual'),
    },
    'pubkeys.tls_hardwaremanager': {
        'description':  ('Fingerprint of the TLS certificate recognized as'
                         'belonging to the hardware manager of the server'),
    },
    'pubkeys.ssh': {
        'description': ('Fingerprint of the SSH key of the OS running on the '
                        'system.'),
    },
}
