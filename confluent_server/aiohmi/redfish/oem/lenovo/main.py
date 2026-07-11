# Copyright 2019 Lenovo Corporation
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
from aiohmi.redfish.oem.lenovo import tsma
from aiohmi.redfish.oem.lenovo import xcc
from aiohmi.redfish.oem.lenovo import xcc3
from aiohmi.redfish.oem.lenovo import smm3
import aiohmi.exceptions as exc

async def get_handler(sysinfo, sysurl, webclient, cache, cmd, rootinfo={}):
    if not sysinfo:  # we are before establishing there is one system, and one manager...
        systems, status = await webclient.grab_json_response_with_status('/redfish/v1/Systems')
        if status == 401:
            raise exc.PyghmiException('Access Denied')
        if status == 200:
            for system in systems.get('Members', []):
                if system.get('@odata.id', '').endswith('/1'):
                    sysurl = system['@odata.id']
                    sysinfo, status = await webclient.grab_json_response_with_status(sysurl)
                    break
    leninf = sysinfo.get('Oem', {}).get('Lenovo', {})
    mgrinfo = {}
    if leninf:
        mgrinfo, status = await webclient.grab_json_response_with_status('/redfish/v1/Managers/1')
        if status != 200:
            mgrinfo = {}
    if not leninf:
        bmcinfo = await cmd.bmcinfo()
        if 'Ami' in bmcinfo.get('Oem', {}):
            return await tsma.TsmHandler.create(sysinfo, sysurl, webclient, cache, gpool=cmd._gpool)
    elif 'xclarity controller' in mgrinfo.get('Model', '').lower():
        if mgrinfo['Model'].endswith('3'):
            return await xcc3.OEMHandler.create(sysinfo, sysurl, webclient, cache,
                                   gpool=cmd._gpool)
        else:
            return await xcc.OEMHandler.create(sysinfo, sysurl, webclient, cache,
                                  gpool=cmd._gpool)
    elif 'FrontPanelUSB' in leninf or 'USBManagementPortAssignment' in leninf or sysinfo.get('SKU', '').startswith('7X58'):
        return await xcc.OEMHandler.create(sysinfo, sysurl, webclient, cache,
                              gpool=cmd._gpool)
    else:
        leninv = sysinfo.get('Links', {}).get('OEM', {}).get(
            'Lenovo', {}).get('Inventory', {})
        if 'hdd' in leninv and 'hostMAC' in leninv and 'backPlane' in leninv:
            return await tsma.TsmHandler.create(sysinfo, sysurl, webclient, cache,
                                   gpool=cmd._gpool)
    try:
        devdesc = await webclient.grab_json_response_with_status('/DeviceDescription.json')
        if devdesc[1] == 200:
            if devdesc[0]['type'].lower() in ('lenovo-smm3', 'smm3'):
                return await smm3.OEMHandler.create(sysinfo, sysurl, webclient, cache,
                                                    gpool=cmd._gpool)
    except Exception:
        pass
    return await generic.OEMHandler.create(sysinfo, sysurl, webclient, cache,
                                           gpool=cmd._gpool)
