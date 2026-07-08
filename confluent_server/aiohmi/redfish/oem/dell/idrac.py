# Copyright 2022 Lenovo Corporation
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

import aiohmi.exceptions as exc
import aiohmi.redfish.oem.generic as generic


class OEMHandler(generic.OEMHandler):

    def __init__(self):
        super(OEMHandler, self).__init__()
        # attribute name -> owning DellAttributes resource URL, populated
        # by get_bmc_configuration and required by set_bmc_configuration
        # to route each change to the correct resource
        self._attrurlbyname = {}

    async def set_bootdev(self, bootdev, persist=False, uefiboot=None,
                    fishclient=None):
        # gleaned from web console, under configuration, system settings,
        # hardware, first boot device. iDrac presumes that the standard
        # explicitly refers only to physical devices. I think the intent
        # is the exact opposite for 'removable' media, and thus redirect
        # the 'physical' standard to the vFDD/VCD-DVD seen in the idrac
        # web gui
        if bootdev not in ('floppy', 'cd'):
            return await super(OEMHandler, self).set_bootdev(
                bootdev, persist, uefiboot, fishclient)
        payload = {'Attributes': {}}
        if persist:
            payload['Attributes']['ServerBoot.1.BootOnce'] = 'Disabled'
        else:
            payload['Attributes']['ServerBoot.1.BootOnce'] = 'Enabled'
        if bootdev == 'floppy':
            payload['Attributes']['ServerBoot.1.FirstBootDevice'] = 'vFDD'
        elif bootdev == 'cd':
            payload['Attributes']['ServerBoot.1.FirstBootDevice'] = 'VCD-DVD'
        await fishclient._do_web_request(
            '/redfish/v1/Managers/iDRAC.Embedded.1/Attributes',
            payload, method='PATCH', etag='*')
        return {'bootdev': bootdev}

    async def _get_attribute_urls(self):
        # The iDRAC exposes its configuration as three OEM attribute
        # resources (iDRAC, System, and LifecycleController scopes),
        # linked from the manager via Links.Oem.Dell.DellAttributes
        mgrurl = await self.get_default_mgrurl()
        mgrinfo = await self._do_web_request(mgrurl)
        atturls = []
        dellattrs = mgrinfo.get('Links', {}).get('Oem', {}).get(
            'Dell', {}).get('DellAttributes', [])
        for attmember in dellattrs:
            atturl = attmember.get('@odata.id', None)
            if atturl:
                atturls.append(atturl)
        if not atturls:
            # older firmware without the DellAttributes links; the manager
            # scope attributes are still available at a fixed location
            atturls = [mgrurl + '/Attributes']
        return atturls

    async def get_bmc_configuration(self):
        settings = {}
        self._attrurlbyname = {}
        for atturl in await self._get_attribute_urls():
            attrs = await self._do_web_request(atturl)
            for attname in attrs.get('Attributes', {}):
                settings[attname] = {
                    'value': attrs['Attributes'][attname]}
                self._attrurlbyname[attname] = atturl
        return settings

    async def set_bmc_configuration(self, changeset):
        if not self._attrurlbyname:
            currsettings = await self.get_bmc_configuration()
        else:
            currsettings = None
        updates = {}
        for key in changeset:
            currval = changeset[key]
            if isinstance(currval, dict):
                currval = currval.get('value', None)
            attrurl = self._attrurlbyname.get(key, None)
            if not attrurl:
                raise exc.InvalidParameterValue(
                    'Unknown attribute {0}'.format(key))
            if attrurl not in updates:
                updates[attrurl] = {}
            updates[attrurl][key] = currval
        # attributes are typed in the iDRAC; values arrive as strings from
        # the caller, so coerce integers by the type of the current value
        if currsettings is None:
            currsettings = await self.get_bmc_configuration()
        for attrurl in updates:
            for key in updates[attrurl]:
                currtype = type(currsettings.get(key, {}).get('value', ''))
                if currtype is int and isinstance(updates[attrurl][key], str):
                    try:
                        updates[attrurl][key] = int(updates[attrurl][key])
                    except ValueError:
                        pass
            await self._do_web_request(
                attrurl, {'Attributes': updates[attrurl]}, method='PATCH',
                etag='*')
            self._invalidate_url_cache(attrurl)
