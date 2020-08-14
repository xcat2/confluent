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
import codecs
import confluent.discovery.handlers.imm as immhandler
import confluent.exceptions as exc
import confluent.netutil as netutil
import confluent.util as util
import errno
import eventlet
import eventlet.support.greendns
import json
import os
import pyghmi.exceptions as pygexc
import eventlet.green.socket as socket
webclient = eventlet.import_patched('pyghmi.util.webclient')
import struct
getaddrinfo = eventlet.support.greendns.getaddrinfo


def fixup_uuid(uuidprop):
    baduuid = ''.join(uuidprop.split())
    uuidprefix = (baduuid[:8], baduuid[8:12], baduuid[12:16])
    a = codecs.encode(struct.pack('<IHH', *[int(x, 16) for x in uuidprefix]), 'hex')
    a = util.stringify(a)
    uuid = (a[:8], a[8:12], a[12:16], baduuid[16:20], baduuid[20:])
    return '-'.join(uuid).upper()




class NodeHandler(immhandler.NodeHandler):
    devname = 'XCC'

    def __init__(self, info, configmanager):
        self._wc = None
        self.nodename = None
        self.tmpnodename = None
        self.tmppasswd = None
        self._atdefaultcreds = True
        self._needpasswordchange = True
        self._currcreds = (None, None)
        super(NodeHandler, self).__init__(info, configmanager)

    @classmethod
    def adequate(cls, info):
        # We can sometimes receive a partially initialized SLP packet
        # This is not adequate for being satisfied
        return bool(info.get('attributes', {}))

    def preconfig(self, possiblenode):
        self.tmpnodename = possiblenode
        ff = self.info.get('attributes', {}).get('enclosure-form-factor', '')
        if ff not in ('dense-computing', [u'dense-computing']):
            # skip preconfig for non-SD530 servers
            return
        self.trieddefault = None  # Reset state on a preconfig attempt
        # attempt to enable SMM
        #it's normal to get a 'not supported' (193) for systems without an SMM
        # need to branch on 3.00+ firmware
        currfirm = self.info.get('attributes', {}).get('firmware-image-info', [''])[0]
        currfirm = currfirm.split(':')
        if len(currfirm) > 1:
            currfirm = float(currfirm[1])
        disableipmi = False
        if currfirm >= 3:
            # IPMI is disabled and we need it, also we need to go to *some* password
            wc = self.wc
            if not wc:
                # We cannot try to enable SMM here without risking real credentials
                # on the wire to untrusted parties
                return
            wc.grab_json_response('/api/providers/logout')
            wc.set_basic_credentials(self._currcreds[0], self._currcreds[1])
            rsp = wc.grab_json_response('/redfish/v1/Managers/1/NetworkProtocol')
            if not rsp.get('IPMI', {}).get('ProtocolEnabled', True):
                disableipmi = True
                _, _ = wc.grab_json_response_with_status(
                    '/redfish/v1/Managers/1/NetworkProtocol',
                    {'IPMI': {'ProtocolEnabled': True}}, method='PATCH')
        ipmicmd = None
        try:
            ipmicmd = self._get_ipmicmd(self._currcreds[0], self._currcreds[1])
            ipmicmd.xraw_command(netfn=0x3a, command=0xf1, data=(1,))
        except pygexc.IpmiException as e:
            if (e.ipmicode != 193 and 'Unauthorized name' not in str(e) and
                    'Incorrect password' not in str(e) and
                    str(e) != 'Session no longer connected'):
                # raise an issue if anything other than to be expected
                if disableipmi:
                    _, _ = wc.grab_json_response_with_status(
                        '/redfish/v1/Managers/1/NetworkProtocol',
                        {'IPMI': {'ProtocolEnabled': False}}, method='PATCH')
                raise
            self.trieddefault = True
        if disableipmi:
            _, _ = wc.grab_json_response_with_status(
                '/redfish/v1/Managers/1/NetworkProtocol',
                {'IPMI': {'ProtocolEnabled': False}}, method='PATCH')
        #TODO: decide how to clean out if important
        #as it stands, this can step on itself
        #if ipmicmd:
        #    ipmicmd.ipmi_session.logout()

    def validate_cert(self, certificate):
        # broadly speaking, merely checks consistency moment to moment,
        # but if https_cert gets stricter, this check means something
        fprint = util.get_fingerprint(self.https_cert)
        return util.cert_matches(fprint, certificate)

    def get_webclient(self, username, password, newpassword):
        wc = self._wc.dupe()
        try:
            wc.connect()
        except socket.error as se:
            if se.errno != errno.ECONNREFUSED:
                raise
            return (None, None)
        pwdchanged = False
        adata = json.dumps({'username': util.stringify(username),
                            'password': util.stringify(password)
                            })
        headers = {'Connection': 'keep-alive',
                   'Content-Type': 'application/json'}
        wc.request('POST', '/api/login', adata, headers)
        rsp = wc.getresponse()
        if rsp.status != 200 and password == 'PASSW0RD':
            rsp.read()
            adata = json.dumps({
                'username': username,
                'password': newpassword,
                })
            headers = {'Connection': 'keep-alive',
                       'Content-Type': 'application/json'}
            wc.request('POST', '/api/login', adata, headers)
            rsp = wc.getresponse()
            if rsp.status == 200:
                pwdchanged = True
                password = newpassword
            else:
                rsp.read()
                return (None, None)
        if rsp.status == 200:
            self._currcreds = (username, password)
            wc.set_basic_credentials(username, password)
            rspdata = json.loads(rsp.read())
            wc.set_header('Content-Type', 'application/json')
            wc.set_header('Authorization', 'Bearer ' + rspdata['access_token'])
            if '_csrf_token' in wc.cookies:
                wc.set_header('X-XSRF-TOKEN', wc.cookies['_csrf_token'])
            if rspdata.get('pwchg_required', None) == 'true':
                wc.request('POST', '/api/function', json.dumps(
                    {'USER_UserPassChange': '1,{0}'.format(newpassword)}))
                rsp = wc.getresponse()
                rsp.read()
                if rsp.status != 200:
                    return (None, None)
                self._currcreds = (username, newpassword)
                wc.set_basic_credentials(username, newpassword)
                pwdchanged = True
            if '_csrf_token' in wc.cookies:
                wc.set_header('X-XSRF-TOKEN', wc.cookies['_csrf_token'])
            if pwdchanged:
                # Remove the minimum change interval, to allow sane 
                # password changes after provisional changes
                wc = self.wc
                self.set_password_policy('', wc)
            return (wc, pwdchanged)
        return (None, None)

    @property
    def wc(self):
        passwd = None
        isdefault = True
        if self._wc is None:
            self._wc = webclient.SecureHTTPConnection(
                self.ipaddr, 443, verifycallback=self.validate_cert)
            self._wc.connect()
        nodename = None
        if self.nodename:
            nodename = self.nodename
            inpreconfig = False
        elif self.tmpnodename:
            nodename = None
            inpreconfig = True
        if self._currcreds[0] is not None:
            wc, pwdchanged = self.get_webclient(self._currcreds[0], self._currcreds[1], None)
            if wc:
                return wc
        if nodename:
            creds = self.configmanager.get_node_attributes(
                nodename, ['secret.hardwaremanagementuser',
                'secret.hardwaremanagementpassword'], decrypt=True)
            user, passwd, isdefault = self.get_node_credentials(
                nodename, creds, 'USERID', 'PASSW0RD')
        if not self.trieddefault:
            if not passwd:
                # So in preconfig context, we don't have admin permission to
                # actually divulge anything to the target
                # however the target *will* demand a new password... if it's currently
                # PASSW0RD
                # use TempW0rd42 to avoid divulging a real password on the line
                # This is replacing one well known password (PASSW0RD) with another
                # (TempW0rd42)
                passwd = 'TempW0rd42'
            wc, pwdchanged = self.get_webclient('USERID', 'PASSW0RD', passwd)
            if wc:
                if pwdchanged:
                    if inpreconfig:
                        self.tmppasswd = passwd
                    else:
                        self._needpasswordchange = False
                return wc
        self.trieddefault = True
        if isdefault:
            return
        self._atdefaultcreds = False
        if self.tmppasswd:
            wc, _ = self.get_webclient('USERID', self.tmppasswd, passwd)
        else:
            wc, _ = self.get_webclient(user, passwd, None)
        if wc:
            return wc

    def set_password_policy(self, strruleset, wc):
        ruleset = {'USER_GlobalMinPassChgInt': '0'}
        for rule in strruleset.split(','):
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
        try:
            wc.grab_json_response('/api/dataset', ruleset)
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
        if self._needpasswordchange and self.tmppasswd != passwd:
            wc.grab_json_response('/api/function',
                                {'USER_UserPassChange': '{0},{1}'.format(uid, passwd)})
        if username != 'USERID':
            wc.grab_json_response(
                '/api/function',
                {'USER_UserModify': '{0},{1},,1,4,0,0,0,0,,8,'.format(uid, username)})
            self.tmppasswd = None
        self._currcreds = (username, passwd)

    def _convert_sha256account(self, user, passwd, wc):
        # First check if the specified user is sha256...
        userinfo = wc.grab_json_response('/api/dataset/imm_users')
        curruser = None
        uid = None
        user = util.stringify(user)
        passwd = util.stringify(passwd)
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
                wc.grab_json_response('/api/providers/logout')
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
                    userparams = "{0},{1},{2},1,4,0,0,0,0,,8,".format(curruser['users_user_id'], user, tpass)
                    nwc.grab_json_response('/api/function', {'USER_UserCreate': userparams})
                    nwc.grab_json_response('/api/providers/logout')
                    nwc, pwdchanged = self.get_webclient(user, tpass, passwd)
                    if not pwdchanged:
                        nwc.grab_json_response(
                            '/api/function',
                            {'USER_UserPassChange': '{0},{1}'.format(curruser['users_user_id'], passwd)})
                    nwc.grab_json_response('/api/providers/logout')
            finally:
                self._wc = None
                wc = self.wc
                wc.grab_json_response('/api/function', {'USER_UserDelete': "{0},{1}".format(tmpuid, '6pmu0ezczzcp')})
                wc.grab_json_response('/api/providers/logout')

    def config(self, nodename, reset=False):
        self.nodename = nodename
        # TODO(jjohnson2): set ip parameters, user/pass, alert cfg maybe
        # In general, try to use https automation, to make it consistent
        # between hypothetical secure path and today.
        dpp = self.configmanager.get_node_attributes(
            nodename, 'discovery.passwordrules')
        strruleset = dpp.get(nodename, {}).get(
            'discovery.passwordrules', {}).get('value', '')
        wc = self.wc
        creds = self.configmanager.get_node_attributes(
            self.nodename, ['secret.hardwaremanagementuser',
            'secret.hardwaremanagementpassword'], decrypt=True)
        user, passwd, isdefault = self.get_node_credentials(nodename, creds, 'USERID', 'PASSW0RD')
        self.set_password_policy(strruleset, wc)
        if self._atdefaultcreds:
            if isdefault and self.tmppasswd:
                raise Exception(
                    'Request to use default credentials, but refused by target after it has been changed to {0}'.format(self.tmppasswd))
            if not isdefault:
                self._setup_xcc_account(user, passwd, wc)
        self._convert_sha256account(user, passwd, wc)
        cd = self.configmanager.get_node_attributes(
            nodename, ['secret.hardwaremanagementuser',
                       'secret.hardwaremanagementpassword',
                       'hardwaremanagement.manager', 'hardwaremanagement.method', 'console.method'],
                       True)
        cd = cd.get(nodename, {})
        if (cd.get('hardwaremanagement.method', {}).get('value', 'ipmi') != 'redfish'
                or cd.get('console.method', {}).get('value', None) == 'ipmi'):
            nwc = wc.dupe()
            nwc.set_basic_credentials(self._currcreds[0], self._currcreds[1])
            rsp = nwc.grab_json_response('/redfish/v1/Managers/1/NetworkProtocol')
            if not rsp.get('IPMI', {}).get('ProtocolEnabled', True):
                # User has indicated IPMI support, but XCC is currently disabled
                # change XCC to be consistent
                _, _ = nwc.grab_json_response_with_status(
                        '/redfish/v1/Managers/1/NetworkProtocol',
                        {'IPMI': {'ProtocolEnabled': True}}, method='PATCH')
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
            currinfo = wc.grab_json_response('/api/providers/logoninfo')
            currip = currinfo.get('items', [{}])[0].get('ipv4_address', '')
            # do not change the ipv4_config if the current config looks right already
            if currip != newip:
                statargs = {
                    'ENET_IPv4Ena': '1', 'ENET_IPv4AddrSource': '0',
                    'ENET_IPv4StaticIPAddr': newip, 'ENET_IPv4StaticIPNetMask': newmask
                    }
                if netconfig['ipv4_gateway']:
                    statargs['ENET_IPv4GatewayIPAddr'] = netconfig['ipv4_gateway']
                wc.grab_json_response('/api/dataset', statargs)
        elif self.ipaddr.startswith('fe80::'):
            self.configmanager.set_node_attributes(
                {nodename: {'hardwaremanagement.manager': self.ipaddr}})
        else:
            raise exc.TargetEndpointUnreachable(
                'hardwaremanagement.manager must be set to desired address (No IPv6 Link Local detected)')
        wc.grab_json_response('/api/providers/logout')
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
