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

import aiohmi.redfish.oem.dell.main as dell
import aiohmi.redfish.oem.generic as generic
import aiohmi.redfish.oem.lenovo.main as lenovo
import aiohmi.redfish.oem.ami.main as ami
import aiohmi.redfish.oem.megware.main as megware

OEMMAP = {
    'Lenovo': lenovo,
    'Dell': dell,
    'AMI': ami,
    'Ami': ami,
    'Megware': megware,
}


def get_oem_handler(sysinfo, sysurl, webclient, cache, cmd, rootinfo={}):
    if rootinfo.get('Vendor', None) in OEMMAP:
        return OEMMAP[rootinfo['Vendor']].get_handler(sysinfo, sysurl,
                                                     webclient, cache, cmd, rootinfo)
    for oem in sysinfo.get('Oem', {}):
        if oem in OEMMAP:
            return OEMMAP[oem].get_handler(sysinfo, sysurl, webclient, cache,
                                           cmd, rootinfo)
    for oem in sysinfo.get('Links', {}).get('OEM', []):
        if oem in OEMMAP:
            return OEMMAP[oem].get_handler(sysinfo, sysurl, webclient, cache,
                                           cmd, rootinfo)
    if rootinfo:  # rootinfo indicates early invocation, bmcinfo not ready yet
        return generic.OEMHandler(sysinfo, sysurl, webclient, cache, cmd._gpool, rootinfo)    
    bmcinfo = cmd.bmcinfo
    for oem in bmcinfo.get('Oem', {}):
        if oem in OEMMAP:
            return OEMMAP[oem].get_handler(sysinfo, sysurl, webclient, cache,
                                           cmd, rootinfo)
    return generic.OEMHandler(sysinfo, sysurl, webclient, cache, cmd._gpool, rootinfo)
