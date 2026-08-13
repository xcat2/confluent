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

import os

import aiohmi.redfish.oem.generic as generic
import aiohmi.util.webclient as webclient
from urllib.parse import urlencode
import aiohmi.exceptions as pygexc


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

    # Auxiliary power cycle, offered by the chassis on the megarac based systems
    # that have an aux power domain to cycle
    _auxresetaction = '#NvidiaChassis.AuxPowerReset'

    async def reseat_bay(self, bay):
        if bay != -1:
            raise pygexc.UnsupportedFunctionality(
                'This is not an enclosure manager')
        chassiscol = await self._do_web_request('/redfish/v1/Chassis')
        for chassis in chassiscol.get('Members', []):
            chassisinfo = await self._do_web_request(chassis['@odata.id'])
            action = chassisinfo.get('Actions', {}).get('Oem', {}).get(
                self._auxresetaction, {}).get('target', None)
            if action:
                await self._do_web_request(action,
                                           {'ResetType': 'AuxPowerCycle'})
                return
        raise pygexc.UnsupportedFunctionality(
            'Reseat is not supported on this platform')

    def format_messages(self, response):
        msgs = response.get('Messages', [])
        msgents = []
        for msg in msgs:
            msgents.append(self.format_message(msg))
        for msg in response.get('Oem', {}).get('Ami', {}).get('HMCMessages', []):
            msgents.append(self.format_messages(msg))
        return ';'.join(msgents)

    # What to keep across a firmware update, for the builds that let us say.
    # SDR is excluded because a new firmware image is expected to bring its own.
    _preserveconfig = {
        'Syslog': True,
        'NTP': True,
        'Network': True,
        'Authentication': True,
        'EXTLOG': True,
        'FRU': True,
        'IPMI': True,
        'KVM': True,
        'REDFISH': True,
        'SDR': False,
        'SEL': True,
        'SNMP': True,
        'SSH': True,
        'WEB': True,
    }

    async def _preserve_configuration(self):
        """Ask the bmc to keep its configuration across the update.

        Builds differ in which settings they are willing to preserve, and they
        reject the whole request if it names one they do not know, so send only
        the intersection with what this bmc advertises.
        """
        usd = await self._do_web_request('/redfish/v1/UpdateService', cache=False)
        advertised = usd.get('Oem', {}).get('AMIUpdateService', {}).get(
            'PreserveConfiguration', None)
        if not advertised:
            return
        preserve = {k: v for k, v in self._preserveconfig.items() if k in advertised}
        if not preserve:
            return
        await self._do_web_request('/redfish/v1/UpdateService', {
            'Oem': {
                'AMIUpdateService': {
                    '@odata.type': '#AMIUpdateService.v1_0_0.AMIUpdateService',
                    'PreserveConfiguration': preserve,
                }}}, method='PATCH', etag='*')

    async def _allowed_imagetypes(self):
        actinfo = await self._do_web_request(
            '/redfish/v1/UpdateService/SimpleUpdateActionInfo')
        for param in actinfo.get('Parameters', []):
            if param.get('Name', None) == 'ImageType':
                return param.get('AllowableValues', [])
        return []

    async def _checked_imagetype(self, imagetype, filename):
        """Check the image type the parameter file gave against what is accepted.

        Flashing the wrong kind of image is not something to be clever about, so
        the type is asked for rather than worked out from the file.
        """
        allowed = await self._allowed_imagetypes()
        choices = ', '.join(allowed) if allowed else 'BMC, BIOS'
        if not imagetype:
            raise pygexc.InvalidParameterValue(
                'This bmc needs to be told what kind of firmware "{0}" is, '
                'one of: {1}'.format(os.path.basename(filename), choices))
        if allowed and imagetype not in allowed:
            raise pygexc.InvalidParameterValue(
                '"{0}" is not a firmware image type this bmc accepts, it '
                'offers: {1}'.format(imagetype, choices))
        return imagetype

    async def update_firmware(self, filename, data=None, progress=None, bank=None, otherfields=()):
        await self._preserve_configuration()
        otherfields = dict(otherfields) if otherfields else {}
        oemparams = dict(otherfields.get('OemParameters', None) or {})
        imagetype = await self._checked_imagetype(
            oemparams.get('ImageType', None), filename)
        oemparams['ImageType'] = imagetype
        otherfields['OemParameters'] = oemparams
        # Updating the bmc takes the bmc away mid flight, which is expected
        # rather than a failure to watch the update
        self._updateresetsbmc = imagetype == 'BMC'
        try:
            return await super().update_firmware(filename, data, progress, bank, otherfields)
        finally:
            self._updateresetsbmc = False


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
            # The header MegaRAC checks is spelled without separators; with
            # X-CSRF-Token every subsequent call answers Invalid Authentication
            wc.set_header('X-CSRFTOKEN', rsp['CSRFToken'])
        self._wc = wc
        return wc
