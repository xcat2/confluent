# vim: tabstop=4 shiftwidth=4 softtabstop=4
# Copyright 2013 IBM Corporation
# all rights reserved


#This defines the attributes of variou classes of things

# 'nic', meant to be a nested structure under node
nic = {
    'Name': {
        'description': 'Name in ip/ifconfig as desired by administrator',
    },
    'Port': {
        'description': 'Port that this nic connects to',
    },
    'Switch': {
        'description': 'Switch that this nic connects to',
    },
    'ManagedHardwareAddress': {
        'description': 'Mac address to push to nic',
    },
    'DNSSuffix': {
        'description': ('String to place after nodename, but before'
                        'Network.Domain to derive FQDN for this NIC'),
    },
    'HardwareAddress': {
        'description': 'Hardware address discovered on nic',
    },
    'IPAddresses': {
        'description': 'IPv4 and IPv6 addresses in CIDR format'
    },
    'PVID': {
        'description': 'PVID of port on switch this nic connects to',
    },
    'MTU': {
        'description': 'Requested MTU to configure on this interface',
    },
    'VLANs': {
        'description': 'Tagged VLANs to apply to nic/switch',
    },
    'DHCPv4Enabled': {
        'description':  ('Whether DHCP should be attempted to acquire IPv4'
                         'address on this interface'),
    },
    'DHCPv6Enabled': {
        'description':  ('Whether DHCP should be attempted to acquire IPv6'
                         'address on this interface'),
    },
}


# 'node', which can be considered a 'system' or a 'vm'
node = {
    'Groups': {
        'default': 'all',
        'description': ('List of static groups for which this node is'
                        'considered a member'),
    },
    'Type': {
        'hidden': True,
        # This is used to ascertain if this is a 'system', 'vm', etc...
    },
    'Numeric': {
        'hidden':  True,
        # a number for use in substitutions, not guaranteed to be unique
    },
    'TimeZone': {
        'description': 'POSIX timezone to apply to this node',
    },
    'Operators': {
        'description': 'User(s) granted operator privilege over this node',
    },
    'Status.HealthSummary': {
        'description': ('An assessment of the overall health of the node.  It
                        'can be "optimal", "warning", "critical'"),
    },
    'Status.LastHeartbeat': {
        'description': "Timestamp of last received heartbeat",
    },
    'Status.HeartbeatDeadline': {
        'description': "Time when Heartbeat will be considered expired",
    },
    'Status.DeploymentState': {
        'description': "State of any deployment activity in progress",
    },
    'Network.Gateway': {
        'description': ''''Default gateway to configure node with''',
    },
    'Network.NameServers': {
        'description': '''DNS servers for node to use''',
    },
    'Network.Domain': {
        'description': 'Value to append to nodename, if any, to get FQDN',
    },
    'Network.Interfaces': {
        'listof': 'nic',
        'description': 'List of network interfaces to configure on node',
    },
    'Storage.OSVolume': {
        'default': 'auto',
        'description': 'Description of storage to target when deploying OS',
    },
    'Storage.ClientIQN': {
        'description': ('Indicates IQN used by this node when communicating'
                        'with iSCSI servers'),
    },
    'Storage.iSCSIServer': {
        'description': 'Address of iSCSI server used for boot if applicable',
    },
    'Storage.Pool': {
        'description': ('For scenarios like SAN boot and virtualization, this'
                        'describes the pool to allocate boot volume from'),
    },
    'OS.ImageName': {
        'description': 'The OS Image applied or to be applied to node',
    },
    'Console.Speed': {
        'default': 'auto',
        'description': '''Indicate the speed at which to run serial port.
Default behavior is to autodetect the appropriate value as possible''',
    },
    'Console.Port': {
        'default': 'auto',
        'description': '''Indicate which port to use for text console.  Default
behavior is to auto detect the value appropriate for the platform.  'Disable'
can be used to suppress serial console configuration'''
    },
    'Console.Method': {
        'description': '''Indicate the method used to access the console of
The managed node.'''
    },
    'Virtualization.Host': {
        'description': 'Hypervisor where this node does/should reside',
        'appliesto': ['vm'],
    },
    'Virtualization.ComputePool': {
        'description': ('Set of compute resources this node is permitted to'
                        ' be created on/be migrated to'),
        'appliesto': ['vm'],
    },
    'Virtualization.StorageModel': {
        'description': ('The model of storage adapter to emulate in a virtual'
                        'machine.  Defaults to virtio-blk for KVM, vmscsi for'
                        'VMware'),
        'appliesto': ['vm'],
    },
    'Virtualization.NicModel': {
        'description': ('The model of NIC adapter to emulate in a virtual'
                        'machine.  Defaults to virtio-net for KVM, vmxnet3 for'
                        'VMware'),
        'appliesto': ['vm'],
    },
    'HardwareManagement.Method': {
        'default': 'ipmi',
        'description': '''The method used to perform operations such as power
control. '''
    },
    'Enclosure.Manager': {
        'description': "The management device for this node's chassis",
        'appliesto': ['system'],
    },
    'Enclosure.Bay': {
        'description': 'The bay in the enclosure, if any',
        'appliesto': ['system'],
    },
    'Enclosure.Type': {
        'description': '''The type of enclosure in use (e.g. IBM BladeCenter,
IBM Flex)''',
        'appliesto': ['system'],
    },
    'Identity.SerialNumber': {
        'description': 'The manufacturer serial number of node',
    },
    'Identity.UUID': {
        'description': 'The UUID of the node as presented in DMI',
    },
    'Identity.ModelNumber': {
        'description': 'The manufacturer dictated  model number for the node',
    },
    'Identity.SNMPEngineId': {
        'description': 'The SNMP Engine id used by this node',
    },
    'Credentials.SNMPUser': {
        'description': 'The user to use for SNMPv3 access to this node',
    },
    'Credentials.SNMPPassword': {
        'description': 'The password to use for SNMPv3 access to this node',
    },
    'Credentials.SNMPLocalizedKey': {
        'description': "SNMPv3 key localized to this node's SNMP Engine id",
    },
    'Credentials.SNMPCommunity': {
        'description': 'SNMPv1 community string',
    },
    'Credentials.RootPassword': {
        'description': '''The password to apply to local root account.
The value may be in the clear or already crypted as it would appear in
/etc/shadow''',
    },
    'Credentials.AdministratorPassword': {
        'description': '''The password to apply to local Administrator account.
Due to limitations, this value must be stored in the clear.  A blank value
indicates local Administrrator account be disabled, allowing only AD accounts
access'''
    },
    'Credentials.IPMIUser': {
        'description': '''Username to use by ipmi plugin. If unspecified, the
client behavior will default to USERID. BMC configuration will default to
setting a randomized username.''',
    },
    'Credentials.IPMIPassword': {
        'description': '''Password to use by ipmi plugin.  If unspecified, the
client behavior defaults to PASSW0RD.  BMC configuration defaults to randomized
password to mitigate offline attack risk and eliminate storing a clear text
credential of import on the BMC.'''
    },
    'Credentials.ManagementUser': {
        'description': ('Username to be set and used by protocols like SSH and'
                        ' HTTP'),
    },
    'Credentials.ManagementPassword': {
        'description': ('Password to be set and used by protocols like SSH and'
                        ' HTTP'),
    },
}
