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
        'description': ('The type of node.  This may be switch, server, rackmount, dense, enclosure or not set to be generic.'),
        'validvalues': ('switch', 'server', 'rackmount', 'dense', 'enclosure', ''),
    },
    'crypted.rootpassword': {
        'description': 'The password of the local root password. '
                       'This is stored as a non-recoverable hash. If '
                       'unspecified and confluent is used to deploy, then '
                       'login at console using password will be impossible '
                       'and only key based login can work for root.',
    },
    'crypted.grubpassword': {
        'description': 'Password required to modify grub behavior at boot',
    },
    'crypted.selfapikey': {
        'description': ('Crypt of api key for self api requests by node'),
    },
    'trusted.subnets': {
        'description': 'Remote subnets in CIDR notation that should be considered as trusted as local networks'
    },
    'deployment.encryptboot': {
        'description': ('Specify a strategy for encrypting the volume. Support '
                        'for this setting is currently only enabled for '
                        'RedHat 8 and CentOS 8 profiles. If blank or unset, '
                        'no encryption is done. If set to "tpm2" then the OS '
                        'will freely decrypt so long as the same '
                        'Trusted Platform Module is available to decrypt the '
                        'volume. Note that versions earlier than 8.2 may malfunction '
                        'at boot time if this feature is attempted, depending on configuration.'),
        'validvalues': ('tpm2', 'none', ''),
    },
    'deployment.apiarmed': {
        'description': ('Indicates whether the node authentication token interface '
                        'is armed.  If set to once, it will grant only the next '
                        'request. If set to continuous, will allow many requests, '
                        'which greatly reduces security, particularly when connected to '
                        'untrusted networks. '
                        'Should not be set unless an OS deployment is pending on the node. '
                        'Generally this is not directly modified, but is modified '
                        'by the "nodedeploy" command'),
        'validvalues': ('once', 'continuous', ''),
    },
    'deployment.sealedapikey': {
        'description': 'This attribute is used by some images to save a sealed '
                       'version of a node apikey, so that a subsequent run with '
                       'same TPM2 will use the TPM2 to protect the API key rather '
                       'than local network verification. If this is set, then '
                       'an api key request will receive this if the api key grant '
                       'is not armed',
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
#    'collective.allowedmanagers': {
#        'description': ('Restricted set of deployment and managers in automatic selectien
#    },
#    ssh.equivnodes - control the list of nodes that go into equiv...
    'collective.manager': {
        'description': ('When in collective mode, the member of the '
                        'collective currently considered to be responsible '
                        'for this node.  At a future date, this may be '
                        'modified automatically if another attribute '
                        'indicates candidate managers, either for '
                        'high availability or load balancing purposes.')
    },
    'collective.managercandidates': {
        'description': ('A noderange of nodes permitted to be a manager for '
                        'the node. This controls failover and deployment.  If '
                        'not defined, all managers may deploy and no '
                        'automatic failover will be performed. '
                        'Using this requires that collective members be '
                        'defined as nodes for noderange expansion')
    },
    'deployment.lock': {
        'description': ('Indicates whether deployment actions should be impeded. '
                        'If locked, it indicates that a pending profile should not be applied. '
                        'If "autolock", then locked will be set when current pending deployment completes. '
                         ),
        'validlist':    ('autolock', 'locked')
    },
    'deployment.pendingprofile': {
        'description': ('An OS profile that is pending deployment.  This indicates to '
                        'the network boot subsystem what should be offered when a potential '
                        'network boot request comes in')
    },
    'deployment.stagedprofile': {
        'description': ('A profile that has been staged, but is awaiting final '
                        'boot to be activated. This allows an OS profile to '
                        'remove itself from netboot without indicating '
                        'completion to any watcher.')
    },
    'deployment.profile': {
        'description': ('The profile that has most recently reported '
                        'completion of deployment. Note that an image may opt '
                        'to leave itself both current and pending, for example '
                        'a stateless profile would be both after first boot.')

    },
    'deployment.state': {
        'description': ('Profiles may push more specific state, for example, it may set the state to "failed" or "succeded"'),
    },
    'deployment.state_detail': {
        'description': ('Detailed state information as reported by an OS profile, when available'),
    },
    'deployment.useinsecureprotocols': {
        'description': ('What phase(s) of boot are permitted to use insecure protocols '
                        '(TFTP and HTTP without TLS.  By default, only HTTPS is used.  However '
                        'this is not compatible with most firmware in most scenarios.  Using '
                        '"firmware" as the setting will still use HTTPS after the initial download, '
                        'though be aware that a successful attack during the firmware phase '
                        'will negate future TLS protections.  The value "always" will result in '
                        'tftp/http being used for most of the deployment.  The value "never" will '
                        'allow HTTPS only. Note that Ubuntu will still use HTTP without TLS for '
                        'a phase of the installation process.'),
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
    'discovery.nodeconfig': {
        'description':  'Set of nodeconfig arguments to apply after automatic discovery'

    },
    'discovery.policy': {
        'description':  'Policy to use for auto-configuration of discovered '
                        'and identified nodes. "manual" means nodes are '
                        'detected, but not autoconfigured until a user '
                        'approves. "permissive" indicates to allow discovery, '
                        'so long as the node has no existing public key. '
                        '"open" allows discovery even if a known public key '
                        'is already stored',
        'validlist': ('manual', 'permissive', 'pxe', 'open', 'verified'),
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
        'description': ('Indicate logging level to apply to console. '
                        'Defaults to "full".'),
        'validvalues': ('full', 'memory', 'interactive', 'none'),
    },
    'console.method': {
        'description': ('Indicate the method used to access the console of '
                        'the managed node.  If not specified, then console '
                        'is disabled.  "ipmi" should be specified for most '
                        'systems if console is desired.'),
        'validvalues': ('ssh', 'ipmi', 'openbmc', 'tsmsol', 'vcenter', 'proxmox'),
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
                       'is the address of, for example, the Lenovo XCC.  It may optionally '
                       'include /<prefixlen> CIDR suffix to indicate subnet length, which is '
                       'autodetected by default where possible.',
    },
    'hardwaremanagement.method': {
        'description': 'The method used to perform operations such as power '
                       'control, get sensor data, get inventory, and so on. '
                       'ipmi is used if not specified.'
    },
    'hardwaremanagement.port': {
        'description': 'The port the BMC should be configured to connect to '
                       'network.  This only has effect during deployment and '
                       'does not apply to out of band discovery. Example values '
                       'include "ocp", "ml2", "lom" (for on board port '
                       'shared with operating system), or "dedicated"',
    },
    'hardwaremanagement.vlan': {
        'description': 'The vlan that a BMC should be configured to tag '
                       'traffic. This only has effect during OS deployment '
                       'and does not apply to out of band discovery.',
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
    'net.connection_name': {
        'description': 'Name to use when specifiying a name for connection and/or interface name for a team.  This may be the name of a team interface, '
                       'the connection name in network manager for the interface, or may be installed as an altname '
                       'as supported by the respective OS deployment profiles.  Default is to accept default name for '
                       'a team consistent with the respective OS, or to use the matching original port name as connection name.'
    },
    'net.interface_names': {
        'description': 'Interface name or comma delimited list of names to match for this interface. It is generally recommended '
                       'to leave this blank unless needing to set up interfaces that are not on a common subnet with a confluent server, '
                       'as confluent servers provide autodetection for matching the correct network definition to an interface. '
                       'This would be the default name per the deployed OS and can be a comma delimited list to denote members of '
                       'a team or a single interface for VLAN/PKEY connections.'
    },
    'net.mtu': {
            'description': 'MTU to apply to this connection',
    },
    'net.vlan_id': {
        'description': 'Ethernet VLAN or InfiniBand PKEY to use for this connection. '
                       'Specify the parent device using net.interface_names.'
    },
    'net.ipv4_address': {
        'description': 'When configuring static, use this address.  If '
                       'unspecified, it will check if the node name resolves '
                       'to an IP address.  Additionally, the subnet prefix '
                       'may be specified with a suffix, e.g. "/16".  If not '
                       'specified, it will attempt to autodetect based on '
                       'current network configuration.'
    },
    'net.ipv4_method': {
        'description': 'Whether to use static or dhcp when configuring this '
                       'interface for IPv4. "firmwaredhcp" means to defer to '
                       'external DHCP server during firmware execution, but '
                       'use static for OS. "firmwarenone" means to suppress '
                       'even the no-IP dhcp offers, to fully delegate to an external '
                       'dhcp/pxe configuration, even for confluent deployment.',
        'validvalues': ('dhcp', 'static', 'firmwaredhcp', 'firmwarenone', 'none')
    },
    'net.ipv4_gateway': {
        'description':  'The IPv4 gateway to use if applicable.  As is the '
                        'case for other net attributes, net.eth0.ipv4_gateway '
                        'and similar is accepted.'
    },
    'net.ipv6_address': {
        'description': 'When configuring static, use this address.  If '
                       'unspecified, it will check if the node name resolves '
                       'to an IP address.  Additionally, the subnet prefix '
                       'may be specified with a suffix, e.g. "/64".  If not '
                       'specified, it will attempt to autodetect based on '
                       'current network configuration.'
    },
    'net.ipv6_method': {
        'description': 'Whether to use static or dhcp when configuring this '
                       'interface for IPv6. "firmwaredhcp" means to defer to '
                       'external DHCP server during firmware execution, but '
                       'use static for OS. "firmwarenone" means to suppress '
                       'even the no-IP dhcp offers, to fully delegate to an external '
                       'dhcp/pxe configuration, even for confluent deployment',
        'validvalues': ('dhcp', 'static', 'firmwaredhcp', 'firmwarenone', 'none')
    },
    'net.ipv6_gateway': {
        'description':  'The IPv6 gateway to use if applicable.  As is the '
                        'case for other net attributes, net.eth0.ipv6_gateway '
                        'and similar is accepted.'
    },
    'net.hwaddr': {
        'description': 'The hardware address, aka MAC address of the interface indicated, generally populated by the '
                       'PXE discovery mechanism'
    },
    'net.hostname': {
        'description': 'Used to specify hostnames per interface. Can be a '
                       'comma delimited list to indicate aliases'
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
    'ntp.servers': {
        'description': 'NTP server or servers to provide to node during '
                       'deployment. An OS profile may default to internet NTP, '
                       'depending on default configuration of the respective '
                       'operating system',
    },
    'net.team_mode': {
        'description': 'Indicates that this interface should be a team and what mode or runner to use when teamed. '
                       'If this covers a deployment interface, one of the member interfaces may be brought up as '
                       'a standalone interface until deployment is complete, as supported by the OS deployment profile. '
                       'To support this scenario, the switch should be set up to allow independent operation of member ports (e.g. lacp bypass mode or fallback mode).',
        'validvalues': ('lacp', 'loadbalance', 'roundrobin', 'activebackup', 'none')
    },
    'power.pdu': {
        'description': 'Specifies the managed PDU associated with a power input on the node'
    },
    'power.outlet': {
        'description': 'Species the outlet identifier on the PDU associoted with a power input on the node'
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
    'secret.selfapiarmtoken': {
        'description': 'A one-time use shared secret to authenticate a node api token',
    },
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
                        'manager. Aliases for this attribute include bmcuser and switchuser'),
    },
    'secret.hardwaremanagementpassword': {
        'description': ('Password to use when connecting to the hardware '
                        'manager.  Aliases for this attribute include bmcpass and switchpass'),
    },
    'ssh.trustnodes': {
        'description': ('Nodes that are allowed to ssh into the node, '
                        'expressed in noderange syntax.  This is used during '
                        'deployment if the confluent SSH certificate '
                        'authority is configured.  Default behavior is for '
                        'all nodes to trust each other.'),
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
    'pubkeys.tls': {
        'description': ('Fingerprint of the TLS certificate for service running on host.'),
    },
    'pubkeys.ssh': {
        'description': ('Fingerprint of the SSH key of the OS running on the '
                        'system.'),
    },
    'dns.domain': {
        'description': 'DNS Domain searched by default by the system'
    },
    'dns.servers': {
        'description': 'DNS Server or servers to provide to node',
    },
}
