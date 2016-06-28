# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2016 Lenovo
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

# This provides a simplified wrapper around snmp implementation roughly
# mapping to the net-snmp commands

# net-snmp-python was considered as the API is cleaner, but the ability to
# patch pysnmp to have it be eventlet friendly has caused it's selection
# This module simplifies the complex hlapi pysnmp interface

import confluent.exceptions as exc
import eventlet
from eventlet.support.greendns import getaddrinfo
import socket
snmp = eventlet.import_patched('pysnmp.hlapi')


def _get_transport(name):
    # Annoyingly, pysnmp does not automatically determine ipv6 v ipv4
    res = getaddrinfo(name, 161, 0, socket.SOCK_DGRAM)
    if res[0][0] == socket.AF_INET6:
        return snmp.Udp6TransportTarget(res[0][4])
    else:
        return snmp.UdpTransportTarget(res[0][4])


def walk(server, oid, secret, username=None, context=None):
    """Walk over children of a given OID

    This is roughly equivalent to snmpwalk.  It will automatically try to be
    an snmpbulkwalk if possible.  If username is not given, it is assumed that
    the secret is a community string, and v2c is used.  If a username given,
    it'll assume SHA auth and DES privacy with the secret being the same for
    both.

    :param server: The network name/address to target
    :param oid: The SNMP object identifier
    :param secret: The community string or password
    :param username: The username for SNMPv3
    :param context: The SNMPv3 context or index for community string indexing
    """
    # SNMP is a complicated mess of things.  Will endeavor to shield caller
    # from as much as possible, assuming reasonable defaults where possible.
    # there may come a time where we add more parameters to override the
    # automatic behavior (e.g. DES is weak, so it's a likely candidate to be
    # overriden, but some devices only support DES)
    tp = _get_transport(server)
    ctx = snmp.ContextData(context)
    if '::' in oid:
        mib, field = oid.split('::')
        obj = snmp.ObjectType(snmp.ObjectIdentity(mib, field))
    else:
        obj = snmp.ObjectType(snmp.ObjectIdentity(oid))
    eng = snmp.SnmpEngine()
    if username is None:
        # SNMP v2c
        authdata = snmp.CommunityData(secret, mpModel=1)
    else:
        authdata = snmp.UsmUserData(username, authKey=secret, privKey=secret)
    walking = snmp.bulkCmd(eng, authdata, tp, ctx, 0, 10, obj,
                           lexicographicMode=False)
    for rsp in walking:
        errstr, errnum, erridx, answers = rsp
        if errstr:
            raise exc.TargetEndpointUnreachable(str(errstr))
        elif errnum:
            raise exc.ConfluentException(errnum.prettyPrint())
        for ans in answers:
            yield ans


if __name__ == '__main__':
    import sys
    for kp in walk(sys.argv[1], sys.argv[2], 'public'):
        print(str(kp[0]))
        print(str(kp[1]))
