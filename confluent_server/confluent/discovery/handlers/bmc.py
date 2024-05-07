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

# Provide foundation for general IPMI device configuration

import aiohmi.exceptions as pygexc
import aiohmi.ipmi.command as ipmicommand

import socket

class NodeHandler(generic.NodeHandler):
    DEFAULT_USER = 'USERID'
    DEFAULT_PASS = 'PASSW0RD'

    async def _get_ipmicmd(self, user=None, password=None):
        priv = None
        if user is None or password is None:
            if self.trieddefault:
                raise pygexc.IpmiException()
            priv = 4  # manually indicate priv to avoid double-attempt
        if user is None:
            user = self.DEFAULT_USER
        if password is None:
            password = self.DEFAULT_PASS
        return await ipmicommand.create(self.ipaddr, user, password,
                                   privlevel=priv, keepalive=False)

    def __init__(self, info, configmanager):
        self.trieddefault = None
        super(NodeHandler, self).__init__(info, configmanager)

    def probe(self):
        return
        # TODO(jjohnson2): probe serial number and uuid

    def config(self, nodename, reset=False):
        self._bmcconfig(nodename, reset)

    async def _bmcconfig(self, nodename, reset=False, customconfig=None, vc=None):
        # TODO(jjohnson2): set ip parameters, user/pass, alert cfg maybe
        # In general, try to use https automation, to make it consistent
        # between hypothetical secure path and today.
        creds = self.configmanager.get_node_attributes(
            nodename,
            ['secret.hardwaremanagementuser',
             'secret.hardwaremanagementpassword'], decrypt=True)
        user = creds.get(nodename, {}).get(
            'secret.hardwaremanagementuser', {}).get('value', None)
        passwd = creds.get(nodename, {}).get(
            'secret.hardwaremanagementpassword', {}).get('value', None)
        try:
            ic = await self._get_ipmicmd()
            passwd = self.DEFAULT_PASS
        except pygexc.IpmiException as pi:
            havecustomcreds = False
            if user is not None and user != self.DEFAULT_USER:
                havecustomcreds = True
            else:
                user = self.DEFAULT_USER
            if passwd is not None and passwd != self.DEFAULT_PASS:
                havecustomcreds = True
            else:
                passwd = self.DEFAULT_PASS
            if havecustomcreds:
                ic = await self._get_ipmicmd(user, passwd)
            else:
                raise
        if vc:
            ic.register_key_handler(vc)
        currusers = await ic.get_users()
        lanchan = await ic.get_network_channel()
        userdata = await ic.xraw_command(netfn=6, command=0x44, data=(lanchan,
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
                'secret.hardwaremanagementuser and/or '
                'secret.hardwaremanagementpassword was not configured')
        newuser = cd['secret.hardwaremanagementuser']['value']
        newpass = cd['secret.hardwaremanagementpassword']['value']
        for uid in currusers:
            if currusers[uid]['name'] == newuser:
                # Use existing account that has been created
                newuserslot = uid
                if newpass != passwd:  # don't mess with existing if no change
                    ic.set_user_password(newuserslot, password=newpass)
                    ic = await self._get_ipmicmd(user, passwd)
                    if vc:
                        ic.register_key_handler(vc)
                break
        else:
            newuserslot = lockedusers + 1
            if newuserslot < 2:
                newuserslot = 2
            if newpass != passwd:  # don't mess with existing if no change
                ic.set_user_password(newuserslot, password=newpass)
            ic.set_user_name(newuserslot, newuser)
            if havecustomcreds:
                ic = await self._get_ipmicmd(user, passwd)
                if vc:
                    ic.register_key_handler(vc)
            #We are remote operating on the account we are
            #using, no need to try to set user access
            #ic.set_user_access(newuserslot, lanchan,
            #                   privilege_level='administrator')
        # Now to zap others
        for uid in currusers:
            if uid != newuserslot:
                if uid <= lockedusers:  # we cannot delete, settle for disable
                    ic.disable_user(uid, 'disable')
                else:
                    # lead with the most critical thing, removing user access
                    ic.set_user_access(uid, channel=None, callback=False,
                                       link_auth=False, ipmi_msg=False,
                                       privilege_level='no_access')
                    # next, try to disable the password
                    ic.set_user_password(uid, mode='disable', password=None)
                    # ok, now we can be less paranoid
                    try:
                        ic.user_delete(uid)
                    except pygexc.IpmiException as ie:
                        if ie.ipmicode != 0xd5:  # some response to the 0xff
                            # name...
                            # the user will remain, but that is life
                            raise
        if customconfig:
            customconfig(ic)
        if ('hardwaremanagement.manager' in cd and
                cd['hardwaremanagement.manager']['value'] and
                not cd['hardwaremanagement.manager']['value'].startswith(
                    'fe80::')):
            newip = cd['hardwaremanagement.manager']['value']
            newip = newip.split('/', 1)[0]
            newipinfo = socket.getaddrinfo(newip, 0)[0]
            # This getaddrinfo is repeated in get_nic_config, could be
            # optimized, albeit with a more convoluted api..
            newip = newipinfo[-1][0]
            if ':' in newip:
                raise exc.NotImplementedException('IPv6 remote config TODO')
            netconfig = netutil.get_nic_config(cfg, nodename, ip=newip)
            plen = netconfig['prefix']
            newip = '{0}/{1}'.format(newip, plen)
            currcfg = ic.get_net_configuration()
            if currcfg['ipv4_address'] != newip:
                # do not change the ipv4_config if the current config looks
                # like it is already accurate
                ic.set_net_configuration(ipv4_address=newip,
                                         ipv4_configuration='static',
                                         ipv4_gateway=netconfig[
                                             'ipv4_gateway'])
        elif self.ipaddr.startswith('fe80::'):
            cfg.set_node_attributes(
                {nodename: {'hardwaremanagement.manager': self.ipaddr}})
        else:
            raise exc.TargetEndpointUnreachable(
                'hardwaremanagement.manager must be set to desired address')
        if reset:
            ic.reset_bmc()
        return ic
