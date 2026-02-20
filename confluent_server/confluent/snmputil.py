# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2016-2025 Lenovo
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

import asyncio
import confluent.exceptions as exc
import socket
import pysnmp.hlapi.asyncio as snmp
import pysnmp.smi.rfc1902 as rfc1902

async def _get_transport(name):
    # Annoyingly, pysnmp does not automatically determine ipv6 v ipv4
    res = await asyncio.get_event_loop().getaddrinfo(name, 161, type=socket.SOCK_DGRAM)
    if res[0][0] == socket.AF_INET6:
        return await snmp.Udp6TransportTarget.create(res[0][4], 2)
    else:
        return await snmp.UdpTransportTarget.create(res[0][4], 2)


class Session(object):

    def __init__(self, server, secret, username=None, context=None, privacy_protocol=None):
        """Create a new session to interrogate a switch

        If username is not given, it is assumed that
        the secret is community string, and v2c is used.  If a username given,
        it'll assume SHA auth and DES privacy with the secret being the same
        for both.

        :param server: The network name/address to target
        :param secret: The community string or password
        :param username: The username for SNMPv3
        :param context: The SNMPv3 context or index for community indexing
        """
        self.server = server
        self.context = context
        if username is None:
            # SNMP v2c
            self.authdata = snmp.CommunityData(secret, mpModel=1)
        else:
            if privacy_protocol == 'aes':
                privproto = snmp.usmAesCfb128Protocol
            elif privacy_protocol in ('des', None):
                privproto = snmp.usmDESPrivProtocol
            else:
                raise exc.ConfluentException('Unsupported SNMPv3 privacy protocol '
                                             '{0}'.format(privacy_protocol))
            self.authdata = snmp.UsmUserData(
                username, authKey=secret, privKey=secret,
                authProtocol=snmp.usmHMACSHAAuthProtocol,
                privProtocol=privproto)
        self.eng = snmp.SnmpEngine()

    async def walk(self, oid):
        """Walk over children of a given OID

        This is roughly equivalent to snmpwalk.  It will automatically try to
        be a snmpbulkwalk if possible.

        :param oid: The SNMP object identifier
        """
        # SNMP is a complicated mess of things.  Will endeavor to shield caller
        # from as much as possible, assuming reasonable defaults when possible.
        # there may come a time where we add more parameters to override the
        # automatic behavior (e.g. DES is weak, so it's likely to be
        # overriden, but some devices only support DES)
        tp = await _get_transport(self.server)
        ctx = snmp.ContextData(self.context)
        resolvemib = False
        if '::' in oid:
            resolvemib = True
            mib, field = oid.split('::')
            obj = rfc1902.ObjectType(rfc1902.ObjectIdentity(mib, field))
            obj = snmp.ObjectType(snmp.ObjectIdentity(mib, field))
        else:
            obj = rfc1902.ObjectType(rfc1902.ObjectIdentity(oid))
        walking = snmp.bulk_walk_cmd(self.eng, self.authdata, tp, ctx, 0, 10, obj,
                                   lexicographicMode=False, lookupMib=resolvemib)
        async for rsp in walking:
            errstr, errnum, erridx, answers = rsp
            if errstr:
                errstr = str(errstr)
                finerr = errstr + ' while trying to connect to ' \
                                    '{0}'.format(self.server)
                if errstr in ('Unknown USM user', 'unknownUserName',
                                'wrongDigest', 'Wrong SNMP PDU digest'):
                    raise exc.TargetEndpointBadCredentials(finerr)
                # need to do bad credential versus timeout
                raise exc.TargetEndpointUnreachable(finerr)
            elif errnum:
                raise exc.ConfluentException(errnum.prettyPrint() +
                                                ' while trying to connect to '
                                                '{0}'.format(self.server))
            for ans in answers:
                if not obj[0].isPrefixOf(ans[0]):
                    # PySNMP returns leftovers in a bulk command
                    # filter out such leftovers
                    break
                yield ans
        #except snmperr.WrongValueError:
        #    raise exc.TargetEndpointBadCredentials('Invalid SNMPv3 password')



if __name__ == '__main__':
    import sys
    ts = Session(sys.argv[1], 'public')
    for kp in ts.walk(sys.argv[2]):
        print(str(kp[0]))
        print(str(kp[1]))
