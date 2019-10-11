# Copyright 2019 Lenovo
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
import confluent.util as util
import eventlet.support.greendns
import json
try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode
getaddrinfo = eventlet.support.greendns.getaddrinfo

webclient = eventlet.import_patched('pyghmi.util.webclient')

class NodeHandler(generic.NodeHandler):
    devname = 'TSM'
    DEFAULT_USER = 'USERID'
    DEFAULT_PASS = 'PASSW0RD'

    def __init__(self, info, configmanager):
        self.trieddefault = None
        self.targuser = None
        self.curruser = None
        self.currpass = None
        self.targpass = None
        self.nodename = None
        self.csrftok = None
        self.channel = None
        self.atdefault = True
        super(NodeHandler, self).__init__(info, configmanager)

    def validate_cert(self, certificate):
        # broadly speaking, merely checks consistency moment to moment,
        # but if https_cert gets stricter, this check means something
        fprint = util.get_fingerprint(self.https_cert)
        return util.cert_matches(fprint, certificate)

    def _get_wc(self):
        authdata = {  # start by trying factory defaults
            'username': self.DEFAULT_USER,
            'password': self.DEFAULT_PASS,
        }
        if not self.trieddefault:
            wc = webclient.SecureHTTPConnection(self.ipaddr, 443, verifycallback=self.validate_cert)
            rsp, status = wc.grab_json_response_with_status('/api/session', urlencode(authdata))
            if status > 400:
                rsp = util.stringify(rsp)
                self.trieddefault = True
                if '555' in rsp:
                    passchange = {
                        'Password': self.targpass, 
                        'RetypePassword': self.targpass,
                        'param': 4,
                        'default_password': self.DEFAULT_PASS,
                        'username': self.DEFAULT_USER
                        }
                    rsp, status = wc.grab_json_response_with_status('/api/reset-pass', urlencode(passchange))
                    authdata['password'] = self.targpass
                    rsp, status = wc.grab_json_response_with_status('/api/session', urlencode(authdata))
                    self.csrftok = rsp['CSRFToken']
                    self.channel = rsp['channel']
                    self.curruser = self.DEFAULT_USER
                    self.currpass = self.targpass
                    return wc
            else:
                self.curruser = self.DEFAULT_USER
                self.currpass = self.DEFAULT_PASS
                self.csrftok = rsp['CSRFToken']
                self.channel = rsp['channel']
                return wc
        if self.curruser:
            authdata['username'] = self.curruser
            authdata['password'] = self.currpass
            rsp, status = wc.grab_json_response_with_status('/api/session', urlencode(authdata))
            if rsp.status != 200:
                return None
            self.csrftok = rsp['CSRFToken']
            self.channel = rsp['channel']
            return wc
        authdata['username'] = self.targuser
        authdata['password'] = self.targpass
        rsp, status = wc.grab_json_response_with_status('/api/session', urlencode(authdata))
        if status != 200:
            return None
        self.curruser = self.targuser
        self.currpass = self.targpass
        self.csrftok = rsp['CSRFToken']
        self.channel = rsp['channel']
        return wc

    def config(self, nodename):
        self.nodename = nodename
        creds = self.configmanager.get_node_attributes(
            nodename, ['secret.hardwaremanagementuser',
                       'secret.hardwaremanagementpassword',
                       'hardwaremanagement.manager', 'hardwaremanagement.method', 'console.method'],
                       True)
        cd = creds.get(nodename, {})
        user, passwd, _ = self.get_node_credentials(
                nodename, creds, self.DEFAULT_USER, self.DEFAULT_PASS)
        self.targuser = user
        self.targpass = passwd
        wc = self._get_wc()
        wc.set_header('X-CSRFTOKEN', self.csrftok)
        curruserinfo = {}
        authupdate = False
        wc.set_header('Content-Type', 'application/json')
        if user != self.curruser:
            authupdate = True
            if not curruserinfo:
                curruserinfo = wc.grab_json_response('/api/settings/users')
                authchg = curruserinfo[1]
            authchg['name'] = user
        if passwd != self.currpass:
            authupdate = True
            if not curruserinfo:
                curruserinfo = wc.grab_json_response('/api/settings/users')
                authchg = curruserinfo[1]
            authchg['changepassword'] = 0
            authchg['password_size'] = 'bytes_20'
            authchg['password'] = passwd
            authchg['confirm_password'] = passwd
        if authupdate:
            rsp, status = wc.grab_json_response_with_status('/api/settings/users/2', authchg, method='PUT')
        if (cd.get('hardwaremanagement.method', {}).get('value', 'ipmi') != 'redfish'
                or cd.get('console.method', {}).get('value', None) == 'ipmi'):
            # IPMI must be enabled per user config
            wc.grab_json_response('/api/settings/ipmilanconfig', {
                'ipv4_enable': 1, 'ipv6_enable': 1,
                'uncheckedipv4lanEnable': 0, 'uncheckedipv6lanEnable': 0,
                'checkedipv4lanEnable': 1, 'checkedipv6lanEnable': 1})
        if ('hardwaremanagement.manager' in cd and
                cd['hardwaremanagement.manager']['value'] and
                not cd['hardwaremanagement.manager']['value'].startswith(
                    'fe80::')):
            newip = cd['hardwaremanagement.manager']['value']
            newipinfo = getaddrinfo(newip, 0)[0]
            newip = newipinfo[-1][0]
            if ':' in newip:
                raise exc.NotImplementedException('IPv6 remote config TODO')
            currnet = wc.grab_json_response('/api/settings/network')
            for net in currnet:
                if net['channel_number'] == self.channel and net['lan_enable'] == 0:
                    # ignore false indication and switch to 8 (dedicated)
                    self.channel = 8
                if net['channel_number'] == self.channel:
                    # we have found the interface to potentially manipulate
                    if net['ipv4_address'] != newip:
                        netconfig = netutil.get_nic_config(self.configmanager, nodename, ip=newip)
                        newmask = netutil.cidr_to_mask(netconfig['prefix'])
                        net['ipv4_address'] = newip
                        net['ipv4_subnet'] = newmask
                        if netconfig['ipv4_gateway']:
                            net['ipv4_gateway'] = netconfig['ipv4_gateway']
                        net['ipv4_dhcp_enable'] = 0
                        rsp, status = wc.grab_json_response_with_status(
                            '/api/settings/network/{0}'.format(net['id']), net, method='PUT')
                    break
        elif self.ipaddr.startswith('fe80::'):
            self.configmanager.set_node_attributes(
                {nodename: {'hardwaremanagement.manager': self.ipaddr}})
        else:
            raise exc.TargetEndpointUnreachable(
                'hardwaremanagement.manager must be set to desired address (No IPv6 Link Local detected)')
        rsp, status = wc.grab_json_response_with_status('/api/session', method='DELETE')


if __name__ == '__main__':
    import confluent.config.configmanager as cfm
    c = cfm.ConfigManager(None)
    import sys
    info = {'addresses': [[sys.argv[1]]] }
    print(repr(info))
    testr = NodeHandler(info, c)
    testr.config(sys.argv[2])
