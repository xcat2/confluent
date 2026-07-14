# Copyright 2026 MEGWARE Computer Vertrieb und Service GmbH
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

"""
Discovery handler for Megware EUREKA chassis Redfish service.

This is a software-only Redfish service (not a BMC). It provides
chassis-level information, node inventory, power supply data, and
sensor readings. It does NOT support IPMI, NIC configuration,
firmware update, or other BMC-specific operations.
"""

import confluent.discovery.handlers.generic as generic
import confluent.util as util
import aiohmi.util.webclient as webclient


class NodeHandler(generic.NodeHandler):
    devname = 'EUREKA'
    is_enclosure = True
    maxmacs = 42
    https_supported = True
    DEFAULT_USER = 'admin'
    DEFAULT_PASS = 'admin'

    def __init__(self, info, configmanager):
        self.trieddefault = None
        self.targuser = None
        self.curruser = None
        self.currpass = None
        self.targpass = None
        self.nodename = None
        self.xauthtoken = None
        self.atdefault = True
        super(NodeHandler, self).__init__(info, configmanager)

    def get_firmware_default_account_info(self):
        return (self.DEFAULT_USER, self.DEFAULT_PASS)

    async def scan(self):
        await self.get_https_cert()
        try:
            wc = webclient.WebConnection(
                self.ipaddr, 443, verifycallback=self.validate_cert)
            root = await wc.grab_json_response('/redfish/v1/')
            uuid = root.get('UUID', None)
            if uuid:
                self.info['uuid'] = uuid.lower()

            # Read chassis info for model/serial
            chassis_url = root.get('Chassis', {}).get('@odata.id')
            if chassis_url:
                try:
                    chassis_coll = await wc.grab_json_response(chassis_url)
                    members = chassis_coll.get('Members', [])
                    if members:
                        cinfo = await wc.grab_json_response(members[0]['@odata.id'])
                        if cinfo.get('Model'):
                            self.info['modelname'] = cinfo['Model']
                        if cinfo.get('SerialNumber'):
                            self.info['serialnumber'] = cinfo['SerialNumber']
                        if cinfo.get('Manufacturer'):
                            self.info['modelnumber'] = cinfo['Manufacturer']
                except Exception:
                    pass
        except Exception:
            pass

    async def _get_wc(self):
        await self.get_https_cert()
        defuser, defpass = self.get_firmware_default_account_info()
        wc = webclient.WebConnection(
            self.ipaddr, 443, verifycallback=self.validate_cert)
        wc.set_header('Content-Type', 'application/json')
        wc.set_header('Accept', 'application/json')
        wc.set_header('OData-Version', '4.0')

        if not self.trieddefault:
            # Attempt authentication with default credentials
            wc.set_basic_credentials(defuser, defpass)
            body, status, headers = await wc.grab_response_with_status(
                '/redfish/v1/SessionService/Sessions',
                {'UserName': defuser, 'Password': defpass})
            if status == 201:
                token = headers.get('X-Auth-Token')
                if token:
                    self.curruser = defuser
                    self.currpass = defpass
                    self.xauthtoken = token
                    if 'Authorization' in wc.stdheaders:
                        del wc.stdheaders['Authorization']
                    wc.stdheaders['X-Auth-Token'] = token
                    return wc
            elif status == 401:
                self.trieddefault = True
                try:
                    errinfo = util.json_loads(body)
                    for msg in errinfo.get('@Message.ExtendedInfo', []):
                        if 'PasswordChangeRequired' in msg.get('MessageId', ''):
                            chgurl = msg.get('MessageArgs', [None])[0]
                            if chgurl and self.targpass and self.targpass != defpass:
                                wc.set_basic_credentials(defuser, defpass)
                                wc.set_header('If-Match', '*')
                                rsp, chgstatus = await wc.grab_json_response_with_status(
                                    chgurl,
                                    {'Password': self.targpass},
                                    method='PATCH')
                                if chgstatus >= 200 and chgstatus < 300:
                                    body, status, headers = \
                                        await wc.grab_response_with_status(
                                            '/redfish/v1/SessionService/Sessions',
                                            {'UserName': defuser,
                                             'Password': self.targpass})
                                    if status == 201:
                                        token = headers.get('X-Auth-Token')
                                        if token:
                                            self.curruser = defuser
                                            self.currpass = self.targpass
                                            self.xauthtoken = token
                                            if 'Authorization' in wc.stdheaders:
                                                del wc.stdheaders['Authorization']
                                            wc.stdheaders['X-Auth-Token'] = token
                                            return wc
                except Exception:
                    pass
                # If no password change scenario, try target password
                if self.targuser and self.targpass:
                    wc.set_basic_credentials(self.targuser, self.targpass)
                    body, status, headers = await wc.grab_response_with_status(
                        '/redfish/v1/SessionService/Sessions',
                        {'UserName': self.targuser, 'Password': self.targpass})
                    if status == 201:
                        token = headers.get('X-Auth-Token')
                        if token:
                            self.curruser = self.targuser
                            self.currpass = self.targpass
                            self.xauthtoken = token
                            if 'Authorization' in wc.stdheaders:
                                del wc.stdheaders['Authorization']
                            wc.stdheaders['X-Auth-Token'] = token
                            return wc
            self.trieddefault = True
            return None

        # We have previously established credentials, try to reuse
        if self.curruser and self.currpass:
            wc.set_basic_credentials(self.curruser, self.currpass)
            body, status, headers = await wc.grab_response_with_status(
                '/redfish/v1/SessionService/Sessions',
                {'UserName': self.curruser, 'Password': self.currpass})
            if status == 201:
                token = headers.get('X-Auth-Token')
                if token:
                    self.xauthtoken = token
                    if 'Authorization' in wc.stdheaders:
                        del wc.stdheaders['Authorization']
                    wc.stdheaders['X-Auth-Token'] = token
                    return wc

        # Try target credentials
        if self.targuser and self.targpass:
            wc.set_basic_credentials(self.targuser, self.targpass)
            body, status, headers = await wc.grab_response_with_status(
                '/redfish/v1/SessionService/Sessions',
                {'UserName': self.targuser, 'Password': self.targpass})
            if status == 201:
                token = headers.get('X-Auth-Token')
                if token:
                    self.curruser = self.targuser
                    self.currpass = self.targpass
                    self.xauthtoken = token
                    if 'Authorization' in wc.stdheaders:
                        del wc.stdheaders['Authorization']
                    wc.stdheaders['X-Auth-Token'] = token
                    return wc

        return None

    async def config(self, nodename):
        self.nodename = nodename
        creds = self.configmanager.get_node_attributes(
            nodename,
            ['secret.hardwaremanagementuser',
             'secret.hardwaremanagementpassword'],
            True)
        defuser, defpass = self.get_firmware_default_account_info()
        user, passwd, _ = self.get_node_credentials(
            nodename, creds, defuser, defpass)
        user = util.stringify(user)
        passwd = util.stringify(passwd)
        self.targuser = user
        self.targpass = passwd

        wc = await self._get_wc()
        if wc is None:
            raise Exception('Unable to authenticate to EUREKA chassis')

        # Update credentials if they differ from current
        authupdate = {}
        if user != self.curruser:
            authupdate['UserName'] = user
        if passwd != self.currpass:
            authupdate['Password'] = passwd
        if authupdate:
            srvroot = await wc.grab_json_response('/redfish/v1/')
            asrv = srvroot.get('AccountService', {}).get('@odata.id')
            if asrv:
                acctinfo = await wc.grab_json_response(asrv)
                acctsurl = acctinfo.get('Accounts', {}).get('@odata.id')
                if acctsurl:
                    accts = await wc.grab_json_response(acctsurl)
                    for acctref in accts.get('Members', []):
                        accturl = acctref.get('@odata.id', '')
                        if accturl:
                            acctdata, acctstatus = \
                                await wc.grab_json_response_with_status(accturl)
                            if acctdata.get('UserName') == self.curruser:
                                wc.set_header('If-Match', '*')
                                rsp, status = await wc.grab_json_response_with_status(
                                    accturl, authupdate, method='PATCH')
                                if status >= 200 and status < 300:
                                    self.curruser = user
                                    self.currpass = passwd
                                break

        # Store link-local address if applicable
        if self.ipaddr.startswith('fe80::'):
            await self.configmanager.set_node_attributes(
                {nodename: {'hardwaremanagement.manager': self.ipaddr}})
