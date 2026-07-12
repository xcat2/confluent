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

import asyncio
import copy
import os
import aiohmi.redfish.oem.generic as generic
import aiohmi.constants as pygconst
import aiohmi.util.webclient as webclient
import aiohmi.exceptions as exc
import time
import socket

healthlookup = {
    'ok': pygconst.Health.Ok,
    'critical': pygconst.Health.Critical
}

def _baytonumber(bay):
    try:
        return int(bay)
    except ValueError:
        if len(bay) == 2:
            # Treat a hexadecimal system as a leading decimal digit and letter compile
            # 1a == slot 1, 1b == slot 2, 2a == slot 1, etc..
            try:
                tmp = int(bay, 16)
                return (2 * (tmp >> 4) - 1) + ((tmp & 15) % 10)
            except ValueError:
                return None
    return None


def _baytolabel(bay):
    try:
        baynum =  int(bay)
        if baynum < 1:
            raise exc.UnsupportedFunctionality(
                    'Reseat not supported for whole chassis')
        # need to convert to 1a, 1b, etc...
        vertidx = ((baynum - 1) // 2 + 1) << 4
        horizidx = (baynum - 1) % 2 + 10
        bayid = vertidx | horizidx
        return '{:02x}'.format(bayid)
    except ValueError:
        return bay
    return None

class OEMHandler(generic.OEMHandler):
    async def get_health(self, fishclient, verbose=True):
        rsp = await self._do_web_request('/redfish/v1/Chassis/chassis1')
        health = rsp.get('Status', {}).get('Health', 'Unknown').lower()
        health = healthlookup.get(health, pygconst.Health.Critical)
        return {'health': health}

    async def set_identify(self, on=True, blink=False):
        if on:
            state = 'On'
        elif blink:
            state = 'Blinking'
        else:
            state = 'Off'
        await self._do_web_request('/redfish/v1/Chassis/chassis1', {
            'Oem': {'Lenovo': {'LED': {'IdentifyLED': {
                'State': state
                }}}
            }}, method='PATCH')

    async def get_system_configuration(self, hideadvanced=True, fishclient=None):
        return {}

    async def set_bmc_configuration(self, changeset):
        chassisparms = {}
        nodeparms = {}
        for setting, value in changeset.items():
            if setting == 'chassis_user_cap':
                chassisparms.setdefault('Oem', {}).setdefault('Lenovo', {}).setdefault('PowerCap', {})['UserPowerCap'] = int(value)
            elif setting == 'chassis_user_cap_active':
                capstate = value.lower().startswith('enable')
                chassisparms.setdefault('Oem', {}).setdefault('Lenovo', {}).setdefault('PowerCap', {})['UserPowerCapEnabled'] = capstate
            elif setting.startswith('node_') and setting.endswith('_user_cap'):
                nodeid = setting[5:-13]
                nodeparms.setdefault(nodeid, {}).setdefault('PowerCap', {})['UserPowerCap'] = int(value)
            elif setting.startswith('node_') and setting.endswith('_user_cap_active'):
                nodeid = setting[5:-20]
                capstate = value.lower().startswith('enable')
                nodeparms.setdefault(nodeid, {}).setdefault('PowerCap', {})['UserPowerCapEnabled'] = capstate
        if chassisparms:
            await self._do_web_request('/redfish/v1/Chassis/chassis1', chassisparms, method='PATCH')
        for nodeid, parms in nodeparms.items():
            url = '/redfish/v1/Chassis/chassis1/Oem/Lenovo/Nodes/{}'.format(nodeid)
            await self._do_web_request(url, parms, method='PATCH')

    async def _get_cpu_inventory(self, withids=False):
        # Empty generator: no CPU inventory items for this OEM handler.
        if False:
            yield None

    async def _get_mem_inventory(self, withids=False):
        # Empty generator: no memory inventory items for this OEM handler.
        if False:
            yield None

    async def _get_adp_inventory(self, withids=False, urls=None):
        # Empty generator: no adapter inventory items for this OEM handler.
        if False:
            yield None

    async def _get_disk_inventory(self, withids=False, urls=None):
        # Empty generator: no disk inventory items for this OEM handler.
        if False:
            yield None

    async def get_bmc_configuration(self):
        settings = {}
        rsp = await self._do_web_request('/redfish/v1/Chassis/chassis1')
        chassiscap = rsp.get('Oem', {}).get('Lenovo', {}).get('PowerCap', {})
        usercap = chassiscap.get('UserPowerCap', None)
        capstate = chassiscap.get('UserPowerCapEnabled', False)
        mincap = chassiscap.get('MinimumPowerCap', None)
        maxcap = chassiscap.get('MaximumPowerCap', None)
        settings['chassis_user_cap'] = {
            'value': usercap,
            'help': 'Specify a maximum wattage to consume, this specific '
                    'system implements a range from {0} to {1}.'.format(
                        mincap, maxcap)
        }
        settings['chassis_user_cap_active'] = {
            'value': 'Enable' if capstate else 'Disable',
            'help': 'Specify whether the user capping setting should be '
                    'used or not at the chassis level.',
        }
        rsp = await self._get_expanded_data('/redfish/v1/Chassis/chassis1/Oem/Lenovo/Nodes')
        for noderesp in rsp.get('Members', []):
            nodeid = noderesp.get('Id', 'unknown')
            nodecap = noderesp.get('PowerCap', {})
            usercap = nodecap.get('UserPowerCap', None)
            capstate = nodecap.get('UserPowerCapEnabled', False)
            mincap = nodecap.get('MinimumPowerCap', None)
            maxcap = nodecap.get('MaximumPowerCap', None)
            settings['node_{}_user_cap'.format(nodeid)] = {
                'value': usercap,
                'help': 'Specify a maximum wattage to consume for node '
                        '{}, this specific node implements a range from '
                        '{} to {}.'.format(
                            nodeid, mincap, maxcap)
            }
            settings['node_{}_user_cap_active'.format(nodeid)] = {
                'value': 'Enable' if capstate else 'Disable',
                'help': 'Specify whether the user capping setting should be '
                        'used or not at the node {} level.'.format(nodeid),
            }
        return settings

    async def retrieve_firmware_upload_url(self):
        # SMMv3 needs to do the non-multipart upload
        usd = await self._do_web_request('/redfish/v1/UpdateService', cache=False)
        if usd.get('HttpPushUriTargetsBusy', False):
                raise exc.TemporaryError('Cannot run multtiple updates to '
                                            'same target concurrently')
        try:
            upurl = usd['HttpPushUri']
        except KeyError:
            raise exc.UnsupportedFunctionality('Redfish firmware update only supported for implementations with push update support')
        if 'HttpPushUriTargetsBusy' in usd:
            await self._do_web_request(
                '/redfish/v1/UpdateService',
                {'HttpPushUriTargetsBusy': True}, method='PATCH')
        return usd,upurl,False

    async def continue_update(self, rsp, progress):
        # SMMv3 does not provide a response, must hardcode the continuation
        # /redfish/v1/UpdateService/FirmwareInventory/fwuimage
        rsp = await self._do_web_request('/redfish/v1/UpdateService/FirmwareInventory/fwuimage')
        for ri in rsp.get('RelatedItem', []):
            targ = ri.get('@odata.id', None)
        parms = {'Oem': {'Lenovo': {'SecureRollBack': False}}}
        rsp = await self._do_web_request('/redfish/v1/UpdateService', parms, method='PATCH')
        targspec = {'target': targ}
        rsp = await self._do_web_request('/redfish/v1/UpdateService/Actions/UpdateService.StartUpdate', targspec)
        monitorurl = rsp.get('@odata.id', None)
        return await self.monitor_update_progress(monitorurl, progress)
        


    async def get_diagnostic_data(self, savefile, progress=None, autosuffix=False):
        tsk = await self._do_web_request(
            '/redfish/v1/Managers/bmc/LogServices/Dump/Actions/LogService.CollectDiagnosticData',
            {"DiagnosticDataType": "Manager"})
        taskrunning = True
        taskurl = tsk.get('@odata.id', None)
        pct = 0 if taskurl else 100
        durl = None
        iters = 0
        while pct < 100 and taskrunning:
            iters += 1
            status = await self._do_web_request(taskurl)
            durl = status.get('AdditionalDataURI', '')
            pct = status.get('PercentComplete', 0)
            if pct <= 0:
                pct = float(iters / 1.3)
                if pct >= 80.0:
                    pct = 80.0
            taskrunning = status.get('TaskState', 'Complete') == 'Running'
            if progress:
                progress({'phase': 'initializing', 'progress': float(pct)})
            if taskrunning:
                await asyncio.sleep(3)
        if not durl:
            for hdr in status.get('Payload', {}).get('HttpHeaders', []):
                if hdr.startswith('Location: '):

                    enturl = hdr.replace('Location: ', '')
                    entryinfo = await self._do_web_request(enturl)
                    durl = entryinfo.get('AdditionalDataURI', None)
                    break
        tries = 0
        while not durl and tries < 60:
            tries += 1
            await asyncio.sleep(3)
            entries = await self._do_web_request('/redfish/v1/Managers/bmc/LogServices/Dump/Entries')
            if progress:
                progress({'phase': 'finalizing', 'progress': float(pct + tries * (100 -pct) / 60)})
            if entries.get('Members', []):
                durl = entries['Members'][0].get('AdditionalDataURI', None)
        if not durl:
            raise Exception("Failed getting service data url")
        fname = os.path.basename(durl)
        if autosuffix and not savefile.endswith('.tar.xz'):
            savefile += time.strftime('-SMM3_%Y%m%d_%H%M%S.tar.xz')
        fd = webclient.make_downloader(self.webclient, durl, savefile)
        while not fd.completed():
            try:
                await fd.join(1)
            except asyncio.TimeoutError:
                pass
            if progress and await fd.get_progress():
                progress({'phase': 'download',
                          'progress': 100 * await fd.get_progress()})
        if fd.exc:
            raise fd.exc
        if progress:
            progress({'phase': 'complete'})
        return savefile

    def _extract_fwinfo(self, inf):
        fwi, url = inf
        currinf = {}
        buildid = fwi.get('Oem', {}).get('Lenovo', {}).get('ExtendedVersion', None)
        if buildid:
            currinf['build'] = buildid
        return currinf


    async def _get_node_info(self):
        nodeinfo = self._varsysinfo
        if not nodeinfo:
            overview = await self._do_web_request('/redfish/v1/')
            chassismembs = overview.get('Chassis', {}).get('@odata.id', None)
            if not chassismembs:
                return nodeinfo
            chassislist = await self._do_web_request(chassismembs)
            chassismembs = chassislist.get('Members', [])
            if len(chassismembs) == 1:
                chassisurl = chassismembs[0]['@odata.id']
                nodeinfo = await self._do_web_request(chassisurl)
        newnodeinfo = copy.deepcopy(nodeinfo)
        newnodeinfo['SKU'] = nodeinfo['Model']
        newnodeinfo['Model'] = 'N1380 Enclosure'
        return newnodeinfo

    async def reseat_bay(self, bay):
        bayid = _baytolabel(bay)
        url = '/redfish/v1/Chassis/chassis1/Oem/Lenovo/Nodes/{}/Actions/Node.Reseat'.format(bayid)
        rsp = await self._do_web_request(url, method='POST')

    async def get_event_log(self, clear=False, fishclient=None):
        async for event in super().get_event_log(clear, fishclient, extraurls=[{'@odata.id':'/redfish/v1/Chassis/chassis1/LogServices/EventLog'}]):
            yield event

    async def get_description(self, fishclient):
        return {'height': 13, 'slot': 0, 'slots': [8, 2]}
