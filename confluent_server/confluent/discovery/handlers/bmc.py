# Copyright 2017 Lenovo
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

import confluent.discovery.handlers.generic as generic
import confluent.exceptions as exc
import confluent.netutil as netutil
import eventlet.support.greendns

# Provide foundation for general IPMI device configuration

import pyghmi.exceptions as pygexc
ipmicommand = eventlet.import_patched('pyghmi.ipmi.command')
ipmicommand.session.select = eventlet.green.select
ipmicommand.session.threading = eventlet.green.threading
ipmicommand.session.socket.getaddrinfo = eventlet.support.greendns.getaddrinfo

DEFAULT_USER = 'USERID'
DEFAULT_PASS = 'PASSW0RD'


class NodeHandler(generic.NodeHandler):

    def _get_ipmicmd(self, user=DEFAULT_USER, password=DEFAULT_PASS):
        return ipmicommand.Command(self.ipaddr, user, password)

    def __init__(self, info, configmanager):
        super(NodeHandler, self).__init__(info, configmanager)

    def probe(self):
        return
        # TODO(jjohnson2): probe serial number and uuid

    def config(self, nodename):
        # TODO(jjohnson2): set ip parameters, user/pass, alert cfg maybe
        # In general, try to use https automation, to make it consistent
        # between hypothetical secure path and today.

        ic = self._get_ipmicmd()
        currusers = ic.get_users()
        lanchan = ic.get_network_channel()
        userdata = ic.xraw_command(netfn=6, command=0x44, data=(lanchan,
                                                                      1))
        userdata = bytearray(userdata['data'])
        maxusers = userdata[0] & 0b111111
        enabledusers = userdata[1] & 0b111111
        lockedusers = userdata[2] & 0b111111
        cfg = self.configmanager
        cd = cfg.get_node_attributes(
            nodename, ['secret.hardwaremanagementuser',
                       'secret.hardwaremanagementpassword',
                       'hardwaremanagement.manager'], True)
        cd = cd.get(nodename, {})
        if ('secret.hardwaremanagementuser' not in cd or
                'secret.hardwaremanagementpassword' not in cd):
            raise exc.TargetEndpointBadCredentials(
                'Missing user and/or password')
        if ('hardwaremanagement.manager' in cd and
                cd['hardwaremanagement.manager']['value'] and
                not cd['hardwaremanagement.manager']['value'].startswith(
                    'fe80::')):
            newip = cd['hardwaremanagement.manager']['value']
            if ':' in newip:
                raise exc.NotImplementedException('IPv6 remote config TODO')
            plen = netutil.get_prefix_len_for_ip(newip)
            newip = '{0}/{1}'.format(newip, plen)
            ic.set_net_configuration(ipv4_address=newip,
                                     ipv4_configuration='static')
        elif self.ipaddr.startswith('fe80::'):
            cfg.set_node_attributes(
                {nodename: {'hardwaremanagement.manager': self.ipaddr}})
        else:
            raise exc.TargetEndpointUnreachable(
                'hardwaremanagement.manager must be set to desired address')
        newuser = cd['secret.hardwaremanagementuser']['value']
        newpass = cd['secret.hardwaremanagementpassword']['value']
        for uid in currusers:
            if currusers[uid]['name'] == newuser:
                # Use existing account that has been created
                newuserslot = uid
                break
        else:
            newuserslot = lockedusers + 1
            if newuserslot < 2:
                newuserslot = 2
            ic.set_user_name(newuserslot, newuser)
            ic.set_user_access(newuserslot, lanchan,
                               privilege_level='administrator')
        if newpass != DEFAULT_PASS:  # don't mess with default if user wants
            ic.set_user_password(newuserslot, password=newpass)
        # Now to zap others
        for uid in currusers:
            if uid != newuserslot:
                if uid <= lockedusers:  # we cannot delete, settle for disable
                    ic.disable_user(uid)
                else:
                    ic.user_delete(uid)
        return
