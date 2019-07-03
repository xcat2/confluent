# Copyright 2017-2019 Lenovo
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

import base64
import confluent.discovery.handlers.imm as immhandler
import confluent.netutil as netutil
import confluent.util as util
import eventlet
import eventlet.support.greendns
import json
import os
import pyghmi.exceptions as pygexc
xcc = eventlet.import_patched('pyghmi.redfish.oem.lenovo.xcc')
import pyghmi.util.webclient as webclient
import struct
getaddrinfo = eventlet.support.greendns.getaddrinfo


def fixup_uuid(uuidprop):
    baduuid = ''.join(uuidprop.split())
    uuidprefix = (baduuid[:8], baduuid[8:12], baduuid[12:16])
    a = struct.pack('<IHH', *[int(x, 16) for x in uuidprefix]).encode('hex')
    uuid = (a[:8], a[8:12], a[12:16], baduuid[16:20], baduuid[20:])
    return '-'.join(uuid).upper()




class NodeHandler(immhandler.NodeHandler):
    devname = 'XCC'

    def __init__(self, info, configmanager):
        self._xcchdlr = None
        self._wc = None
        self.nodename = None
        self._atdefaultcreds = True
        super(NodeHandler, self).__init__(info, configmanager)

    @classmethod
    def adequate(cls, info):
        # We can sometimes receive a partially initialized SLP packet
        # This is not adequate for being satisfied
        return bool(info.get('attributes', {}))

    def preconfig(self):
        ff = self.info.get('attributes', {}).get('enclosure-form-factor', '')
        if ff not in ('dense-computing', [u'dense-computing']):
            return
        self.trieddefault = None  # Reset state on a preconfig attempt
        # attempt to enable SMM
        #it's normal to get a 'not supported' (193) for systems without an SMM
        ipmicmd = None
        try:
            ipmicmd = self._get_ipmicmd()
            ipmicmd.xraw_command(netfn=0x3a, command=0xf1, data=(1,))
        except pygexc.IpmiException as e:
            if (e.ipmicode != 193 and 'Unauthorized name' not in str(e) and
                    'Incorrect password' not in str(e)):
                # raise an issue if anything other than to be expected
                raise
            self.trieddefault = True
        #TODO: decide how to clean out if important
        #as it stands, this can step on itself
        #if ipmicmd:
        #    ipmicmd.ipmi_session.logout()

    def validate_cert(self, certificate):
        # broadly speaking, merely checks consistency moment to moment,
        # but if https_cert gets stricter, this check means something
        fprint = util.get_fingerprint(self.https_cert)
        return util.cert_matches(fprint, certificate)

    @property
    def wc(self):
        if self._wc is None:
            self._wc = webclient.SecureHTTPConnection(
                self.ipaddr, 443, verifycallback=self.validate_cert)
            self._wc.connect()
            self._xcchdlr = xcc.OEMHandler(None, None, self._wc, False)
        if not self.trieddefault:
            self._xcchdlr.set_credentials('USERID', 'PASSW0RD')
            wc = self._xcchdlr.get_webclient()
            if wc:
                return wc
        self.trieddefault = True
        creds = self.configmanager.get_node_attributes(
            self.nodename, ['secret.hardwaremanagementuser',
            'secret.hardwaremanagementpassword'], decrypt=True)
        user, passwd, isdefault = self.get_node_credentials(
            self.nodename, creds, 'USERID', 'PASSW0RD')
        if isdefault:
            return
        self._atdefaultcreds = False
        self._xcchdlr.set_credentials(user, passwd)
        wc = self._xcchdlr.get_webclient()
        if wc:
            return wc

    def set_password_policy(self, ic):
        ruleset = {'USER_GlobalMinPassChgInt': '0'}
        for rule in self.ruleset.split(','):
            if '=' not in rule:
                continue
            name, value = rule.split('=')
            if value.lower() in ('no', 'none', 'disable', 'disabled'):
                value = '0'
            if name.lower() in ('expiry', 'expiration'):
                ruleset['USER_GlobalPassExpPeriod'] = value
                if int(value) < 5:
                    ruleset['USER_GlobalPassExpWarningPeriod'] = value
            if name.lower() in ('lockout', 'loginfailures'):
                if value.lower() in ('no', 'none', 'disable', 'disabled'):
                    value = '0'
                ruleset['USER_GlobalMaxLoginFailures'] = value
            if name.lower() == 'complexity':
                ruleset['USER_GlobalPassComplexRequired'] = value
            if name.lower() == 'reuse':
                ruleset['USER_GlobalMinPassReuseCycle'] = value
        ic.register_key_handler(self.validate_cert)
        ic.oem_init()
        try:
            ic._oem.immhandler.wc.grab_json_response('/api/dataset', ruleset)
        except Exception as e:
            print(repr(e))
            pass

    def _get_next_userid(self, wc):
        userinfo = wc.grab_json_response('/api/dataset/imm_users')
        userinfo = userinfo['items'][0]['users']
        for user in userinfo:
            if user['users_user_name'] == '':
                return user['users_user_id']

    def _setup_xcc_account(self, username, passwd, wc):
        userinfo = wc.grab_json_response('/api/dataset/imm_users')
        uid = None
        for user in userinfo['items'][0]['users']:
            if user['users_user_name'] == username:
                uid = user['users_user_id']
                break
        else:
            for user in userinfo['items'][0]['users']:
                if user['users_user_name'] == 'USERID':
                    uid = user['users_user_id']
                    break
        if not uid:
            raise Exception("XCC has neither the default user nor configured user")
        # The following will work if the password is force change or normal..
        wc.grab_json_response('/api/function',
                             {'USER_UserPassChange': '{0},{1}'.format(uid, passwd)})
        if username != 'USERID':
            wc.grab_json_response(
                '/api/function',
                {'USER_UserModify': '{0},{1},,1,4,0,0,0,0,,8,'.format(uid, username)})

    def _convert_sha256account(self, user, passwd, wc):
        # First check if the specified user is sha256...
        userinfo = wc.grab_json_response('/api/dataset/imm_users')
        curruser = None
        uid = None
        for userent in userinfo['items'][0]['users']:
            if userent['users_user_name'] == user:
                curruser = userent
                break
        if curruser.get('users_pass_is_sha256', 0):
            self._wc = None
            wc = self.wc
            nwc = wc.dupe()
            # Have to convert it for being useful with most Lenovo automation tools
            # This requires deleting the account entirely and trying again
            tmpuid = self._get_next_userid(wc)
            try:
                tpass = base64.b64encode(os.urandom(9)) + 'Iw47$'
                userparams = "{0},6pmu0ezczzcp,{1},1,4,0,0,0,0,,8,".format(tmpuid, tpass)
                result = wc.grab_json_response('/api/function', {'USER_UserCreate': userparams})
                adata = json.dumps({
                    'username': '6pmu0ezczzcp',
                    'password': tpass,
                })
                headers = {'Connection': 'keep-alive', 'Content-Type': 'application/json'}
                nwc.request('POST', '/api/login', adata, headers)
                rsp = nwc.getresponse()
                if rsp.status == 200:
                    rspdata = json.loads(rsp.read())
                    nwc.set_header('Content-Type', 'application/json')
                    nwc.set_header('Authorization', 'Bearer ' + rspdata['access_token'])
                    if '_csrf_token' in wc.cookies:
                        nwc.set_header('X-XSRF-TOKEN', wc.cookies['_csrf_token'])
                    if rspdata.get('reason', False):
                        newpass = base64.b64encode(os.urandom(9)) + 'q4J$'
                        nwc.grab_json_response(
                            '/api/function',
                            {'USER_UserPassChange': '{0},{1}'.format(tmpuid, newpass)})
                    nwc.grab_json_response('/api/function', {'USER_UserDelete': "{0},{1}".format(curruser['users_user_id'], user)})
                    userparams = "{0},{1},{2},1,4,0,0,0,0,,8,".format(curruser['users_user_id'], user, passwd)
                    nwc.grab_json_response('/api/function', {'USER_UserCreate': userparams})
            finally:
                self._wc = None
                self.wc.grab_json_response('/api/function', {'USER_UserDelete': "{0},{1}".format(tmpuid, '6pmu0ezczzcp')})

    def config(self, nodename, reset=False):
        self.nodename = nodename
        # TODO(jjohnson2): set ip parameters, user/pass, alert cfg maybe
        # In general, try to use https automation, to make it consistent
        # between hypothetical secure path and today.
        dpp = self.configmanager.get_node_attributes(
            nodename, 'discovery.passwordrules')
        self.ruleset = dpp.get(nodename, {}).get(
            'discovery.passwordrules', {}).get('value', '')
        wc = self.wc
        creds = self.configmanager.get_node_attributes(
            self.nodename, ['secret.hardwaremanagementuser',
            'secret.hardwaremanagementpassword'], decrypt=True)
        user, passwd, isdefault = self.get_node_credentials(nodename, creds, 'USERID', 'PASSW0RD')
        if self._atdefaultcreds:
            if not isdefault:
                self._setup_xcc_account(user, passwd, wc)
        self._convert_sha256account(user, passwd, wc)
        cd = self.configmanager.get_node_attributes(
            nodename, ['secret.hardwaremanagementuser',
                       'secret.hardwaremanagementpassword',
                       'hardwaremanagement.manager'], True)
        cd = cd.get(nodename, {})
        if ('hardwaremanagement.manager' in cd and
                cd['hardwaremanagement.manager']['value'] and
                not cd['hardwaremanagement.manager']['value'].startswith(
                    'fe80::')):
            newip = cd['hardwaremanagement.manager']['value']
            newipinfo = getaddrinfo(newip, 0)[0]
            newip = newipinfo[-1][0]
            if ':' in newip:
                raise exc.NotImplementedException('IPv6 remote config TODO')
            netconfig = netutil.get_nic_config(self.configmanager, nodename, ip=newip)
            newmask = netutil.cidr_to_mask(netconfig['prefix'])
            # do not change the ipv4_config if the current config looks
            statargs = {'ENET_IPv4Ena': '1', 'ENET_IPv4AddrSource': '0', 'ENET_IPv4StaticIPAddr': newip, 'ENET_IPv4StaticIPNetMask': newmask}
            if netconfig['ipv4_gateway']:
                statargs['ENET_IPv4GatewayIPAddr'] = netconfig['ipv4_gateway']
            wc.grab_json_response('/api/dataset', statargs)
        elif self.ipaddr.startswith('fe80::'):
            self.configmanager.set_node_attributes(
                {nodename: {'hardwaremanagement.manager': self.ipaddr}})
        else:
            raise exc.TargetEndpointUnreachable(
                'hardwaremanagement.manager must be set to desired address (No IPv6 Link Local detected)')
        ff = self.info.get('attributes', {}).get('enclosure-form-factor', '')
        if ff not in ('dense-computing', [u'dense-computing']):
            return
        enclosureuuid = self.info.get('attributes', {}).get('chassis-uuid', [None])[0]
        if enclosureuuid:
            enclosureuuid = enclosureuuid.lower()
            em = self.configmanager.get_node_attributes(nodename,
                                                        'enclosure.manager')
            em = em.get(nodename, {}).get('enclosure.manager', {}).get(
                'value', None)
            # ok, set the uuid of the manager...
            if em:
                self.configmanager.set_node_attributes(
                    {em: {'id.uuid': enclosureuuid}})
