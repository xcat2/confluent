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

import aiohmi.redfish.oem.generic as generic


class OEMHandler(generic.OEMHandler):

    async def set_bootdev(self, bootdev, persist=False, uefiboot=None,
                          fishclient=None):
        # gleaned from web console, under configuration, system settings,
        # hardware, first boot device. iDrac presumes that the standard
        # explicitly refers only to physical devices. I think the intent
        # is the exact opposite for 'removable' media, and thus redirect
        # the 'physical' standard to the vFDD/VCD-DVD seen in the idrac
        # web gui
        if bootdev not in ('floppy', 'cd'):
            return await super(OEMHandler, self).set_bootdev(bootdev, persist,
                                                             uefiboot, fishclient)
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
            payload, method='PATCH')
        return {'bootdev': bootdev}
