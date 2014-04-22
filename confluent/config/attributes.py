# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
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


#This defines the attributes of variou classes of things

# 'nic', meant to be a nested structure under node
nic = {
    'name': {
        'description': 'Name in ip/ifconfig as desired by administrator',
    },
    'port': {
        'description': 'Port that this nic connects to',
    },
    'switch': {
        'description': 'Switch that this nic connects to',
    },
    'customhardwareaddress': {
        'description': 'Mac address to push to nic',
    },
    'dnssuffix': {
        'description': ('String to place after nodename, but before'
                        'Network.Domain to derive FQDN for this NIC'),
    },
    'hardwareaddress': {
        'description': 'Active mac address on this nic (factory or custom)'
    },
    'ipaddresses': {
        'description': 'Set of IPv4 and IPv6 addresses in CIDR format'
    },
    'pvid': {
        'description': 'PVID of port on switch this nic connects to',
    },
    'mtu': {
        'description': 'Requested MTU to configure on this interface',
    },
    'vlans': {
        'description': 'Tagged VLANs to apply to nic/switch',
    },
    'dhcpv4enabled': {
        'description':  ('Whether DHCP should be attempted to acquire IPv4'
                         'address on this interface'),
    },
    'dhcpv6enabled': {
        'description':  ('Whether DHCP should be attempted to acquire IPv6'
                         'address on this interface'),
    },
}

user = {
    'passphrase': {
        'description':  'The passphrase used to authenticate this user'
    },
}

# 'node', which can be considered a 'system' or a 'vm'
node = {
    'groups': {
        'type': list,
        'default': 'all',
        'description': ('List of static groups for which this node is '
                        'considered a member'),
    },
    #'type': {
    #    'description': ('Classification of node as system, vm, etc')
    #},
    #'id': {
    #    'description': ('Numeric identifier for node')
    #},
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
                        '"none". Defaults to "full".')
    },
    'console.method': {
        'description': ('Indicate the method used to access the console of '
                        'the managed node.')
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
        'description': 'The management address dedicated to this node',
    },
    'hardwaremanagement.method': {
        'description': 'The method used to perform operations such as power '
                       'control, get sensor data, get inventory, and so on. '
    },
#    'enclosure.manager': {
#        'description': "The management device for this node's chassis",
#        'appliesto': ['system'],
#    },
#    'enclosure.bay': {
#        'description': 'The bay in the enclosure, if any',
#        'appliesto': ['system'],
#    },
#    'enclosure.type': {
#        'description': '''The type of enclosure in use (e.g. IBM BladeCenter,
#IBM Flex)''',
#        'appliesto': ['system'],
#    },
#    'inventory.serialnumber': {
#        'description': 'The manufacturer serial number of node',
#    },
#    'inventory.uuid': {
#        'description': 'The UUID of the node as presented in DMI',
#    },
#    'inventory.modelnumber': {
#        'description': 'The manufacturer dictated  model number for the node',
#    },
#    'inventory.snmpengineid': {
#        'description': 'The SNMP Engine id used by this node',
#    },
#    'secret.snmpuser': {
#        'description': 'The user to use for SNMPv3 access to this node',
#    },
#    'secret.snmppassphrase': {
#        'description': 'The passphrase to use for SNMPv3 access to this node',
#    },
#    'secret.snmplocalizedkey': {
#        'description': ("SNMPv3 key localized to this node's SNMP Engine id"
#                        'This can be used in lieu of snmppassphrase to avoid'
#                        'retaining the passphrase TODO: document procedure'
#                        'to commit passphrase to localized key'),
#    },
#    'secret.snmpcommunity': {
#        'description': ('SNMPv1 community string, it is highly recommended to'
#                        'step up to SNMPv3'),
#    },
#    'secret.localadminpassphrase': {
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
        'description': 'Optional Integrity key for IPMI communication'
    },
#    'secret.ipmiuser': {
#        'description': ('The username to use to log into IPMI device related '
#                        'to the node.  For setting username, default '
#                        'behavior is to randomize username, for using '
#                        'username if not set, USERID is assumed'),
#    },
#    'secret.ipmipassphrase': {
#        'description': ('The key to use to authenticate to IPMI device '
#                        'related to the node.  For setting passphrase, '
#                        'default behavior is to randomize passphrase and '
#                        'store it here.  If going to connect over the '
#                        'network and value is not set, PASSW0RD is attempted')
#    },
    'secret.hardwaremanagementuser': {
        'description': ('Username to be set and used by protocols like SSH '
                        'and HTTP where client provides passphrase over the '
                        'network. Given the distinct security models betwen '
                        'this class of protocols and SNMP and IPMI, snmp and '
                        'ipmi utilize dedicated values.'),
    },
    'secret.hardwaremanagementpassphrase': {
        'description': ('Passphrase to be set and used by protocols like SSH '
                        'and HTTP, where client sends passphrase over the '
                        'network.  Given distinct security models between '
                        'this class of protocols, SNMP, and IPMI, SNMP and '
                        'IPMI are given their own settings with distinct '
                        'behaviors'),
    },
}
