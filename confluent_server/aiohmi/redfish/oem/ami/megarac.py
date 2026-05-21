# Copyright 2025 Lenovo Corporation
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

import aiohmi.redfish.oem.generic as generic
import aiohmi.util.webclient as webclient
from urllib.parse import urlencode


class OEMHandler(generic.OEMHandler):
    @classmethod
    async def create(cls, sysinfo, sysurl, webclient, cache, gpool=None):
        self = await super().create(sysinfo, sysurl, webclient, cache,
                                         gpool)
        if sysurl is None:
            systems, status = await webclient.grab_json_response_with_status('/redfish/v1/Systems')
            if status == 200:
                for system in systems.get('Members', []):
                    if system.get('@odata.id', '').endswith('/Self') or system.get('@odata.id', '').endswith('/System_0'):
                        sysurl = system['@odata.id']
                        break
            self._varsysurl = sysurl
        self._wc = None
        self.bmc = webclient.thehost
        self._certverify = webclient.verifycallback
        return self
    

    async def get_wc(self):
        self.fwid = None
        if self._wc:
            rsp, status = await self._wc.grab_json_response_with_status('/api/chassis-status')
            if status == 200:
                return self._wc
        authdata = {
            'username': self.username,
            'password': self.password
        }
        wc = webclient.WebConnection(self.bmc, 443, verifycallback=self._certverify)
        wc.set_header('Content-Type', 'application/x-www-form-urlencoded')
        rsp, status = await wc.grab_json_response_with_status('/api/session', method='POST', data=urlencode(authdata))
        if status < 200 or status >= 300:
            raise Exception('Failed to authenticate to BMC')
        if 'CSRFToken' in rsp:
            self.csrftok = rsp['CSRFToken']
            wc.set_header('X-CSRF-Token', rsp['CSRFToken'])
        self._wc = wc
        return wc
