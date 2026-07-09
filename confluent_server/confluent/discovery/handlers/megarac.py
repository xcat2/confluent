# Copyright 2024 Lenovo
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

import asyncio

import confluent.discovery.handlers.redfishbmc as redfishbmc
from aiohmi.util import webclient
from urllib.parse import urlencode


class NodeHandler(redfishbmc.NodeHandler):

    def get_firmware_default_account_info(self):
        return ('admin', 'admin')

    async def _get_wc(self):
        await self.get_https_cert()
        defuser, defpass = self.get_firmware_default_account_info()
        wc = webclient.WebConnection(self.ipaddr, 443, verifycallback=self.validate_cert)
        wc.set_basic_credentials(self.targuser, self.targpass)
        wc.set_header('Host', 'credible-bmc')
        wc.set_header('Content-Type', 'application/json')
        wc.set_header('Accept', 'application/json')
        self.curruser = self.targuser
        rsp, status = await wc.grab_json_response_with_status('/redfish/v1/Managers')
        if status == 200:
            self.currpass = self.targpass
            return wc
        wc.set_header('Content-Type', 'application/x-www-form-urlencoded')
        if self.targuser != defuser:
            wc.set_basic_credentials(defuser, self.targpass)
            rsp, status = await wc.grab_json_response_with_status('/redfish/v1/Managers')
            if status == 200:
                self.curruser = defuser
                self.currpass = self.targpass
                return wc
        authdata = {
            'username': defuser,
            'password': defpass
        }
        rsp, status = await wc.grab_json_response_with_status('/api/session', data=urlencode(authdata))
        if status != 200:
            raise Exception("Target BMC does not recognize firmware default credentials nor the confluent stored credential")
        if rsp.get('passwordStatus', None) == 1:  # change required
            xsrf = rsp.get('CSRFToken', None)
            if xsrf:
                wc.set_header('X-Csrftoken', xsrf)
            authdata = {
                'username': self.targuser,
                'password': self.targpass
            }
            rsp, status = await wc.grab_json_response_with_status('/api/updatenew_password', data=urlencode(authdata))
            if status == 200:
                self.curruser = self.targuser
                self.currpass = self.targpass
                wc.set_header('Content-Type', 'application/json')
                wc.set_basic_credentials(self.targuser, self.targpass)
                return wc
            raise Exception('Failure updating password: ' + repr(rsp))
        self.curruser = defuser
        return wc

    async def get_manager_url(self, wc):
        mgrs = (await self.srvroot(wc)).get('Managers', {}).get('@odata.id', None)
        if not mgrs:
            raise Exception("No Managers resource on BMC")
        rsp = await wc.grab_json_response(mgrs)
        if len(rsp.get('Members', [])) != 1:
            urls = []
            for member in rsp.get('Members', []):
                url = member.get('@odata.id', 'Unknown')
                if 'HGX_BMC' in url:
                    continue
                urls.append(url)
            if len(urls) == 1:
                return urls[0]
            raise Exception("Can not handle multiple Managers")
        mgrurl = rsp['Members'][0]['@odata.id']
        return mgrurl



async def remote_nodecfg(nodename, cfm):
    cfg = cfm.get_node_attributes(
            nodename, 'hardwaremanagement.manager')
    ipaddr = cfg.get(nodename, {}).get('hardwaremanagement.manager', {}).get(
        'value', None)
    ipaddr = ipaddr.split('/', 1)[0]
    ipaddr = (await asyncio.get_running_loop().getaddrinfo(ipaddr, 0))[0][-1]
    if not ipaddr:
        raise Exception('Cannot remote configure a system without known '
                        'address')
    info = {'addresses': [ipaddr]}
    nh = NodeHandler(info, cfm)
    await nh.config(nodename)


if __name__ == '__main__':
    import confluent.config.configmanager as cfm
    c = cfm.ConfigManager(None)
    import sys
    info = {'addresses': [[sys.argv[1]]]}
    print(repr(info))
    testr = NodeHandler(info, c)
    testr.config(sys.argv[2])

