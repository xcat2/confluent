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
import json
import re
import aiohmi.constants as pygconst
import aiohmi.redfish.oem.generic as generic
import aiohmi.exceptions as pygexc
import aiohmi.util.webclient as webclient
import aiohmi.storage as storage
import aiohmi.ipmi.private.util as util
import os.path
import zipfile

numregex = re.compile('([0-9]+)')

def naturalize_string(key):
    """Analyzes string in a human way to enable natural sort

    :param key: string for the split
    :returns: A structure that can be consumed by 'sorted'
    """
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split(numregex, key)]

def natural_sort(iterable):
    """Return a sort using natural sort if possible

    :param iterable:
    :return:
    """
    try:
        return sorted(iterable, key=naturalize_string)
    except TypeError:
        # The natural sort attempt failed, fallback to ascii sort
        return sorted(iterable)

class SensorReading(object):
    def __init__(self, healthinfo, sensor=None, value=None, units=None,
                 unavailable=False):
        if sensor:
            self.name = sensor['name']
        else:
            self.name = healthinfo['name']
            self.health = healthinfo['health']
            self.states = healthinfo['states']
            self.state_ids = healthinfo.get('state_ids', None)
        self.value = value
        self.imprecision = None
        self.units = units
        self.unavailable = unavailable

class OEMHandler(generic.OEMHandler):

    @classmethod
    async def create(cls, sysinfo, sysurl, webclient, cache, gpool=None):
        self = await super(OEMHandler, cls).create(sysinfo, sysurl, webclient, cache,
                                         gpool)
        self.datacache = {}
        return self

    async def weblogout(self):
        if self.webclient:
            try:
                await self.webclient.grab_json_response('/logout')
            except Exception:
                pass
    
    def get_cached_data(self, attribute, age=30):
        try:
            kv = self.datacache[attribute]
            if kv[1] > util._monotonic_time() - age:
                return kv[0]
        except KeyError:
            return None
    
    async def get_inventory(self, withids=False):
        sysinfo = {
            'UUID': self._varsysinfo.get('UUID', '').lower(),
            'Serial Number': self._varsysinfo.get('SerialNumber', ''),
            'Manufacturer': self._varsysinfo.get('Manufacturer', ''),
            'Product name': self._varsysinfo.get('Model', ''),
            'Model': self._varsysinfo.get(
                'SKU', self._varsysinfo.get('PartNumber', '')),
        }
        yield ('System', sysinfo)
        async for cpuinv in self._get_cpu_inventory():
            yield cpuinv
        async for meminv in self._get_mem_inventory():
            yield meminv
        hwmap = await self.hardware_inventory_map()
        for key in natural_sort(hwmap):
            yield (key, hwmap[key])
    
    async def hardware_inventory_map(self):
        hwmap = self.get_cached_data('lenovo_cached_hwmap')
        if hwmap:
            return hwmap
        hwmap = {}
        async for disk in self.disk_inventory(mode=1):  # hardware mode
            hwmap[disk[0]] = disk[1]
        adapterdata = self.get_cached_data('lenovo_cached_adapters')
        if not adapterdata:
            # if self.updating:
            #     raise pygexc.TemporaryError(
            #         'Cannot read extended inventory during firmware update')
            if self.webclient:
                adapterdata = []
                async for adata in self._do_bulk_requests([i['@odata.id'] for i in (await self.webclient.grab_json_response(
                        '/redfish/v1/Chassis/1'))['Links']['PCIeDevices']]):
                    adapterdata.append(adata)           
                if adapterdata:
                    self.datacache['lenovo_cached_adapters'] = (
                        adapterdata, util._monotonic_time())
        if adapterdata:
            anames = {}
            for adata, _ in adapterdata:
                skipadapter = False
                clabel = adata['Slot']['Location']['PartLocation'].get('LocationType','')
                if not clabel:
                    clabel = adata['Slot']['Location']['PartLocation'].get('ServiceLabel', '').split("=")[0]                
                if clabel != 'Embedded':
                    aslot = adata['Slot']['Location']['PartLocation']['LocationOrdinalValue']
                    clabel = 'Slot {0}'.format(aslot)
                aname = adata['Name']
                bdata = {'location': clabel, 'name': aname}
                if aname in anames:
                    anames[aname] += 1
                    aname = '{0} {1}'.format(aname, anames[aname])
                else:
                    anames[aname] = 1
                pcislot = adata['Id'].split('_')[1]
                bdata['pcislot'] = '{0}:{1}.{2}'.format(
                    pcislot[:4].replace('0x',''), pcislot[4:6], pcislot[6:8]
                )
                serialdata = adata.get('SerialNumber', '')
                if (serialdata and serialdata != 'N/A'
                        and '---' not in serialdata):
                    bdata['serial'] = serialdata
                partnum = adata.get('PartNumber', '')
                if partnum and partnum != 'N/A':
                    bdata['Part Number'] = partnum
                fundata = await self._get_expanded_data(adata['PCIeFunctions']['@odata.id'])
                venid = fundata['Members'][0].get('VendorId', None)
                if venid is not None:
                    bdata['PCI Vendor ID'] = venid.lower().split('0x')[-1]
                devid = fundata['Members'][0].get('DeviceId', None)
                if devid is not None and 'PCIE Device ID' not in bdata:
                    bdata['PCI Device ID'] = devid.lower().split('0x')[-1]
                subvenid = fundata['Members'][0].get('SubsystemVendorId', None)
                if subvenid is not None:
                    bdata['PCI Subsystem Vendor ID'] = subvenid.lower().split('0x')[-1]
                subdevid = fundata['Members'][0].get('SubsystemId', None)
                if subdevid is not None:
                    bdata['PCI Subsystem Device ID'] = subdevid.lower().split('0x')[-1]
                bdata['FRU Number'] = adata.get('SKU', '')

                # Could be identified also through Oem->Lenovo->FunctionClass
                if fundata['Members'][0]['DeviceClass'] == 'NetworkController':
                    ports_data = await self._get_expanded_data('{0}/Ports'.format(adata['@odata.id'].replace('PCIeDevices','NetworkAdapters')))
                    macidx = 1
                    for port in ports_data['Members']:
                        if port.get('Ethernet', None):
                            macs = [x for x in port['Ethernet'].get('AssociatedMACAddresses', [])]
                            for mac in macs:
                                label = 'MAC Address {}'.format(macidx)
                                bdata[label] = generic._normalize_mac(mac)
                                macidx += 1
                        ibinfo = port.get('InfiniBand', {})
                        if ibinfo:
                            macs = [x for x in ibinfo.get('AssociatedPortGUIDs', [])]
                            for mac in macs:
                                label = 'Port GUID {}'.format(macidx)
                                bdata[label] = mac
                                macidx += 1                        

                hwmap[aname] = bdata
            self.datacache['lenovo_cached_hwmap'] = (hwmap,
                                                     util._monotonic_time())
        # self.weblogout()
        return hwmap

    def get_disk_firmware(self, diskent, prefix=''):
        bdata = {}
        if not prefix:
            location = diskent.get('Name', '')
            if location.startswith('M.2'):
                prefix = 'M.2-'
            elif location.startswith('7MM'):
                prefix = '7MM-'
        diskname = 'Disk {0}{1}'.format(prefix, diskent['PhysicalLocation']['PartLocation']['LocationOrdinalValue'])
        bdata['model'] = '{0}_{1}'.format(diskent['Manufacturer'].rstrip(), diskent['Model'].rstrip())
        bdata['version'] = diskent.get('FirmwareVersion','')
        return (diskname, bdata)

    def get_disk_hardware(self, diskent, prefix=''):
        bdata = {}
        if not prefix:
            location = diskent.get('Name', '')
            if location.startswith('M.2'):
                prefix = 'M.2-'
            elif location.startswith('7MM'):
                prefix = '7MM-'
        diskname = 'Disk {0}{1}'.format(prefix, diskent['PhysicalLocation']['PartLocation']['LocationOrdinalValue'])
        bdata['Model'] = '{0}_{1}'.format(diskent['Manufacturer'].rstrip(), diskent['Model'].rstrip())
        bdata['Serial Number'] = diskent['SerialNumber'].rstrip()
        bdata['FRU Number'] = diskent['SKU'].rstrip()
        bdata['Description'] = diskent['Oem']['Lenovo']['TypeString'].rstrip()
        return (diskname, bdata)

    async def disk_inventory(self, mode=0):
        # mode 0 is firmware, 1 is hardware
        storagedata = self.get_cached_data('lenovo_cached_storage')
        if not storagedata:
                if self.webclient:
                    chassisinfo = await self.webclient.grab_json_response('/redfish/v1/Chassis/1')
                    storagedata = []
                    async for data in self._do_bulk_requests([i['@odata.id'] for i in chassisinfo['Links']['Drives']]):
                        storagedata.append(data)
                    if storagedata:
                        self.datacache['lenovo_cached_storage'] = (
                            storagedata, util._monotonic_time())
        # Unmanaged disks cannot be retrieved through Redfish API
        if storagedata:
            for diskent, _ in storagedata:
                if mode == 0:
                    yield self.get_disk_firmware(diskent)
                elif mode == 1:
                    yield self.get_disk_hardware(diskent)

    async def get_storage_configuration(self, logout=True):
        rsp = await self._get_expanded_data("/redfish/v1/Systems/1/Storage")
        standalonedisks = []
        pools = []
        for item in rsp.get('Members',[]):
            # Drives shown at 'Direct attached drives' in XCC
            # cannot be used for RAID creation
            if item['Id'].lower() == 'direct_attached_nvme':
                continue            
            cdisks = [item['Drives'][i]['@odata.id'] for i in range(len(item['Drives']))]
            cid = '{0},{1}'.format(
                        item['Id'],
                        item['StorageControllers'][0]['Location']['PartLocation'].get('LocationOrdinalValue', -1))
            if item['Id'].lower() == 'vroc':
                cid = 'vroc,0'            
            storage_pools = await self._get_expanded_data(item['StoragePools']['@odata.id'])
            for p in storage_pools['Members']:
                vols = await self._get_expanded_data(p['AllocatedVolumes']['@odata.id'])
                for vol in vols['Members']:
                    volumes=[]
                    disks=[]
                    spares=[]
                    volumes.append(
                        storage.Volume(name=vol['DisplayName'],
                                    size=int(vol['CapacityBytes'])/1024//1024,
                                    status=vol['Status']['Health'],
                                    id=(cid,vol['Id'])))
                    for item_key, disk_ids in vol['Links'].items():
                        if isinstance(disk_ids, list) and 'drives' in item_key.lower():
                            for disk in disk_ids:
                                if disk['@odata.id'] in cdisks:
                                    cdisks.remove(disk['@odata.id'])
                                disk_data = await self.webclient.grab_json_response(disk['@odata.id'])
                                (spares if disk_data['Oem']['Lenovo']['DriveStatus']=="DedicatedHotspare" else disks).append(
                                    storage.Disk(
                                        name=disk_data['Name'], description=disk_data['Oem']['Lenovo']['TypeString'],
                                        id=(cid, disk_data['Id']), status=disk_data['Oem']['Lenovo']['DriveStatus'],
                                        serial=disk_data['SerialNumber'], fru=disk_data['SKU']))
                    raid=vol['RAIDType']
                totalsize = int(p['Capacity']['Data']['AllocatedBytes'])/1024//1024
                freesize = totalsize - int(p['Capacity']['Data']['ConsumedBytes'])/1024//1024
                pools.append(storage.Array(
                    disks=disks, raid=raid, volumes=volumes,
                    id=(cid, p['Id']), hotspares=spares,
                    capacity=totalsize, available_capacity=freesize))
            for d in cdisks:
                disk_data = await self.webclient.grab_json_response(d)
                standalonedisks.append(
                    storage.Disk(
                        name=disk_data['Name'], description=disk_data['Oem']['Lenovo']['TypeString'],
                        id=(cid, disk_data['Id']), status=disk_data['Oem']['Lenovo']['DriveStatus'],
                        serial=disk_data['SerialNumber'], fru=disk_data['SKU']))
        return storage.ConfigSpec(disks=standalonedisks, arrays=pools)

    async def check_storage_configuration(self, cfgspec=None):
        rsp = await self.webclient.grab_json_response(
            '/api/providers/raidlink_GetStatus')
        if rsp['return'] != 0 or rsp['status'] != 1:
            raise pygexc.TemporaryError('Storage configuration unavailable in '
                                        'current state (try boot to setup or '
                                        'an OS)')
        return True

    async def apply_storage_configuration(self, cfgspec):
        realcfg = await self.get_storage_configuration(False)
        for disk in cfgspec.disks:
            if disk.status.lower() == 'jbod':
                await self._make_jbod(disk, realcfg)
            elif disk.status.lower() == 'hotspare':
                await self._make_global_hotspare(disk, realcfg)
            elif disk.status.lower() in ('unconfigured', 'available', 'ugood',
                                         'unconfigured good'):
                await self._make_available(disk, realcfg)
        for pool in cfgspec.arrays:
            if pool.disks:
                await self._create_array(pool)

    async def _make_available(self, disk, realcfg):
        currstatus = self._get_status(disk, realcfg)
        newstate = None
        if currstatus.lower() == 'unconfiguredgood':
            return
        elif currstatus.lower() == 'globalhotspare':
            newstate = "None"
        elif currstatus.lower() == 'jbod':
            newstate = "MakeUnconfiguredGood"
        await self._set_drive_state(disk, newstate)

    async def _make_jbod(self, disk, realcfg):
        currstatus = self._get_status(disk, realcfg)
        if currstatus.lower() == 'jbod':
            return
        await self._make_available(disk, realcfg)
        await self._set_drive_state(disk, "MakeJBOD")

    async def _make_global_hotspare(self, disk, realcfg):
        currstatus = self._get_status(disk, realcfg)
        if currstatus.lower() == 'globalhotspare':
            return
        await self._make_available(disk, realcfg)
        await self._set_drive_state(disk, "Global")
    
    async def _set_drive_state(self, disk, state):
        raid_alldevices = await self.webclient.grab_json_response(
            '/api/providers/raid_alldevices')
        if raid_alldevices.get('return', -1) != 0:
            raise Exception(
                'Unexpected return to get all RAID devices information')
        for c in raid_alldevices.get('StorageComplexes',[]):
            cslot = str(c.get('SlotNumber'))
            if cslot == disk.id[0].split(',')[1]:
                c_pciaddr = c.get('PCIeAddress',-1)
                cdrives = c.get('Drives',[])
                for d in cdrives:
                    if disk.id[1] == d.get('Id',''):
                        currstatus = d['Oem']['Lenovo']['DriveStatus']
                        d_resid = d['Internal']['ResourceId']
                        if state in ("Global", "None"):
                            data = {
                                "controller_address": c_pciaddr,
                                "drive_resource_id": d_resid,
                                "hotspare_type": state,
                                "pool_resource_ids": []}
                            raidlink_url = '/api/providers/raidlink_AssignHotSpare'
                        else:
                            data = {
                                "controller_address": c_pciaddr,
                                "drive_operation": state,
                                "drive_resource_ids": [d_resid]}
                            raidlink_url = '/api/providers/raidlink_DiskStateAction'
                        msg = await self._do_web_request(raidlink_url, method='POST', 
                                                   payload=data, cache=False)
                        if msg.get('return', -1) != 0:
                            raise Exception(
                                'Unexpected return to set disk state: {0}'.format(
                                msg.get('return', -1)))
                        set_state_token = msg.get('token', '')
                        msg = await self._do_web_request(
                            '/api/providers/raidlink_QueryAsyncStatus',
                            method='POST',
                            payload={"token": set_state_token},
                            cache=False)
                        while msg['status'] == 2:
                            await asyncio.sleep(1)
                            msg = await self._do_web_request(
                            '/api/providers/raidlink_QueryAsyncStatus',
                            method='POST',
                            payload={"token": set_state_token},
                            cache=False)
                        if msg.get('return',-1) != 0 or msg.get('status',-1) != 0:
                            raise Exception(
                                'Unexpected return to set disk state: {0}'.format(
                                msg.get('return', -1)))
                        disk_url=f"/redfish/v1/Systems/1/Storage/{disk.id[0].split(',')[0]}/Drives/{disk.id[1]}"
                        newstatus = await self.webclient.grab_json_response(disk_url)
                        disk_converted = False
                        for _ in range(60):
                            if currstatus == newstatus['Oem']['Lenovo']['DriveStatus']:
                                await asyncio.sleep(1)
                                newstatus = await self.webclient.grab_json_response(disk_url)
                            else:
                                disk_converted = True
                                break
                        if not disk_converted:
                            raise Exception(
                                'Disk set command was successful, but the disk state is unchanged')

    def _get_status(self, disk, realcfg):
        for cfgdisk in realcfg.disks:
            if disk.id == cfgdisk.id:
                currstatus = cfgdisk.status
                break
        else:
            raise pygexc.InvalidParameterValue('Requested disk not found')
        return currstatus
    
    async def remove_storage_configuration(self, cfgspec):
        realcfg = await self.get_storage_configuration(False)
        for pool in cfgspec.arrays:
            for volume in pool.volumes:
                cid = volume.id[0].split(',')[0]
                vid = volume.id[1]
                msg, code = await self.webclient.grab_json_response_with_status(
                    f'/redfish/v1/Systems/1/Storage/{cid}/Volumes/{vid}',
                    method='DELETE')
                if code == 500:
                    raise Exception(
                        'Unexpected return to volume deletion: ' + repr(msg))
        for disk in cfgspec.disks:
            await self._make_available(disk, realcfg)
        self._urlcache.clear()

    def _parse_array_spec(self, arrayspec):
        controller = None
        if arrayspec.disks:
            for disk in list(arrayspec.disks) + list(arrayspec.hotspares):
                if controller is None:
                    controller = disk.id[0]
                if controller != disk.id[0]:
                    raise pygexc.UnsupportedFunctionality(
                        'Cannot span arrays across controllers')
            raidmap = self._raid_number_map(controller)
            if not raidmap:
                raise pygexc.InvalidParameterValue(
                    'No RAID Type supported on this controller')
            requestedlevel = str(arrayspec.raid)
            if requestedlevel not in raidmap:
                raise pygexc.InvalidParameterValue(
                    'Requested RAID Type "{0}" not available on this '
                    'controller. Allowed values are: {1}'.format(
                        requestedlevel, [k for k in raidmap]))
            rdinfo = raidmap[str(arrayspec.raid).lower()]
            rdlvl = str(rdinfo[0])
            defspan = 1 if rdinfo[1] == 1 else 2
            spancount = defspan if arrayspec.spans is None else arrayspec.spans
            drivesperspan = str(len(arrayspec.disks) // int(spancount))
            hotspares = arrayspec.hotspares
            drives = arrayspec.disks
            minimal_conditions = {
                "RAID0": (1,128,1),
                "RAID1": (2,2,1),
                "RAID1Triple": (3,3,1),
                "RAID10": (4,128,2),
                "RAID10Triple": (6,128,3),
                "RAID5": (3,128,1),
                "RAID50": (6,128,2),
                "RAID6": (4,128,1),
                "RAID60": (8, 128, 2)
            }
            raid_level = rdinfo[0]
            min_pd = minimal_conditions[raid_level][0]
            max_pd = minimal_conditions[raid_level][1]
            disk_multiplier = minimal_conditions[raid_level][2]
            if len(drives) < min_pd or \
            len(drives) > max_pd or \
            len(drives) % disk_multiplier != 0:
                raise pygexc.InvalidParameterValue(
                    f'Number of disks for {rdinfo} must be between {min_pd} and {max_pd} and be a multiple of {disk_multiplier}')
            if hotspares:
                hstr = '|'.join([str(x.id[1]) for x in hotspares]) + '|'
            else:
                hstr = ''
            drvstr = '|'.join([str(x.id[1]) for x in drives]) + '|'
            return {
                'controller': controller,
                'drives': drvstr,
                'hotspares': hstr,
                'raidlevel': rdlvl,
                'spans': spancount,
                'perspan': drivesperspan,
            }
        else:
            # TODO(Jarrod Johnson): adding new volume to
            #  existing array would be here
            pass
    
    async def _raid_number_map(self, controller):
        themap = {}
        cid = controller.split(',')
        rsp = await self.webclient.grab_json_response(
            '/redfish/v1/Systems/1/Storage/{0}'.format(cid[0]))
        for rt in rsp['StorageControllers'][0]['SupportedRAIDTypes']:
            rt_lower = rt.lower()
            mapdata = (rt, 1)
            themap[rt]=mapdata
            themap[rt_lower] = mapdata
            themap[rt_lower.replace('raid','r')] = mapdata
            themap[rt_lower.replace('raid','')] = mapdata
        return themap

    async def _create_array(self, pool):
        params = self._parse_array_spec(pool)
        cid = params['controller'].split(',')[0]
        c_capabilities, code = await self.webclient.grab_json_response_with_status(
            f'/redfish/v1/Systems/1/Storage/{cid}/Volumes/Capabilities')
        if code == 404:
            c_capabilities, code = await self.webclient.grab_json_response_with_status(
            f'/redfish/v1/Systems/1/Storage/{cid}/Volumes/Oem/Lenovo/Capabilities')
            if code == 404:
                # If none of the endpoints exist, maybe it should be printed that
                # no capabilities found, therefore default values will be used
                # whatever they are
                pass
        volumes = pool.volumes
        drives = [d for d in params['drives'].split("|") if d != '']
        hotspares = [h for h in params['hotspares'].split("|") if h != '']
        raidlevel = params['raidlevel']
        nameappend = 1
        currvolnames = None
        currcfg = await self.get_storage_configuration(False)
        for vol in volumes:
            if vol.name is None:
                # need to iterate while there exists a volume of that name
                if currvolnames is None:
                    currvolnames = set([])
                    for pool in currcfg.arrays:
                        for volume in pool.volumes:
                            currvolnames.add(volume.name)
                name = 'Volume_{0}'.format(nameappend)
                nameappend += 1
                while name in currvolnames:
                    name = 'Volume_{0}'.format(nameappend)
                    nameappend += 1
            else:
                name = vol.name

            # Won't check against Redfish allowable values as they not trustworthy yet
            # Some values show in Redfish, but may not be accepted by UEFI/controller or vice versa 
            stripsize_map = {
                '4': 4096, '4096': 4096,
                '16': 16384, '16384': 16384,
                '32': 32768, '32768': 32768,
                '64': 65536, '65536': 65536,
                '128': 131072, '131072': 131072,
                '256': 262144, '262144': 262144,
                '512': 524288, '524288': 524288,
                '1024': 1048576, '1048576': 1048576
            }
            stripsize = stripsize_map[str(vol.stripsize).lower().replace('k','')] if vol.stripsize is not None else None

            readpolicy_map = {'0': 'Off', '1': 'ReadAhead'}
            read_policy = None
            read_cache_possible = c_capabilities.get("ReadCachePolicy@Redfish.AllowableValues",[])
            if read_cache_possible:
                if vol.read_policy is not None:
                    if str(vol.read_policy) in readpolicy_map:
                        vol.read_policy = readpolicy_map[str(vol.read_policy)]                    
                    if vol.read_policy in read_cache_possible:
                        read_policy = vol.read_policy
                    else:
                        raise pygexc.InvalidParameterValue(
                        f'{vol.read_policy} Read Cache Policy is not supported. Allowed values are: {read_cache_possible}')
            
            writepolicy_map = {'0': 'WriteThrough', '1': 'UnprotectedWriteBack',
                               '2': 'ProtectedWriteBack', '3': 'Off'}
            write_policy = None
            write_cache_possible = c_capabilities.get("WriteCachePolicy@Redfish.AllowableValues",[])
            if write_cache_possible:
                if vol.write_policy is not None:
                    if str(vol.write_policy) in writepolicy_map:
                        vol.write_policy = writepolicy_map[str(vol.write_policy)]                    
                    if vol.write_policy in write_cache_possible:
                        write_policy = vol.write_policy
                    else:
                        raise pygexc.InvalidParameterValue(
                        f'{vol.write_policy} Write Cache Policy is not supported. Allowed values are: {write_cache_possible}')

            defaultinit_map = {'0': 'No', '1': 'Fast', '2': 'Full'}
            default_init = None
            default_init_possible = c_capabilities.get("InitializationType@Redfish.AllowableValues",[])
            if default_init_possible:
                if vol.default_init is not None:
                    if str(vol.default_init) in defaultinit_map:
                        vol.default_init = defaultinit_map[str(vol.default_init)]
                    if vol.default_init in default_init_possible:
                        default_init = vol.default_init
                    else:
                        raise pygexc.InvalidParameterValue(
                        f'{vol.default_init} Initialization Type is not supported. Allowed values are: {default_init_possible}')

            volsize = None
            spec_disks = sorted(drives)
            spec_hotspares = hotspares
            for array in currcfg.arrays:
                in_use_disks = sorted([d.id[1] for d in array.disks])
                in_use_hotspares = [h.id[1] for h in array.hotspares]
                if spec_disks == in_use_disks:
                    if vol.size is None:
                        volsize = array.available_capacity
                        array.available_capacity = 0
                        break
                    else:
                        strsize = str(vol.size)
                        if strsize in ('all','100%'):
                            raise pygexc.InvalidParameterValue(
                                f'Requested size for volume {name} exceeds available capacity. Available capacity is {array.available_capacity} MiB')
                        elif strsize.endswith('%'):
                            volsize = int(array.capacity
                                        * float(strsize.replace('%', ''))
                                        / 100.0)
                            if volsize > array.available_capacity:
                                raise pygexc.InvalidParameterValue(
                                f'Requested size for volume {name} exceeds available capacity. Available capacity is {array.available_capacity} MiB')
                            else:
                                array.available_capacity-=volsize
                        else:
                            try:
                                volsize = int(strsize)
                                if volsize > array.available_capacity:
                                    raise pygexc.InvalidParameterValue(
                                        f'Requested size for volume {name} exceeds available capacity. Available capacity is {array.available_capacity} MiB')
                                else:
                                    array.available_capacity-=volsize
                            except ValueError:
                                raise pygexc.InvalidParameterValue(
                                    'Unrecognized size ' + strsize)
                elif any(d in in_use_disks for d in spec_disks):
                    raise pygexc.InvalidParameterValue(
                        f'At least one disk from provided config is in use by another volume. To create a volume using the remaining capacity, configure the new volume to use all the following disks: {in_use_disks}')
                else:
                    disks_capacities = {}
                    for d in spec_disks:
                        disks_capacities[d] = (await self.webclient.grab_json_response(
                            f'/redfish/v1/Systems/1/Storage/{cid}/Drives/{d}'))["CapacityBytes"]
                    max_capacity = sum(v for k,v in disks_capacities.items())
                    min_disk = min([v for k,v in disks_capacities.items()])
                    disk_count = len(disks_capacities)
                    max_capacity_per_raid = {
                        "RAID0": max_capacity,
                        "RAID1": min_disk,
                        "RAID1Triple": min_disk,
                        "RAID10": (disk_count//2)*min_disk,
                        "RAID10Triple": (disk_count//3)*min_disk,
                        "RAID5": (disk_count-1)*min_disk,
                        "RAID50": (disk_count-2)*min_disk,
                        "RAID6": (disk_count-2)*min_disk,
                        "RAID60": (disk_count-4)*min_disk
                        }
                    if vol.size is not None:
                        strsize = str(vol.size)
                        if strsize.endswith('%'):
                            volsize = int(max_capacity_per_raid[raidlevel]
                                        * float(strsize.replace('%', ''))
                                        / 100.0)
                        else:
                            try:
                                volsize = int(strsize)
                                if volsize > max_capacity_per_raid[raidlevel]:
                                    raise pygexc.InvalidParameterValue(
                                        f'Requested size for volume {name} exceeds available capacity. Available capacity is {max_capacity_per_raid[raidlevel]} bytes')
                            except ValueError:
                                raise pygexc.InvalidParameterValue(
                                    'Unrecognized size ' + strsize)
                for h in spec_hotspares:
                    if h in in_use_hotspares:
                        raise pygexc.InvalidParameterValue(
                            f'Hotspare {h} from provided config is in use by another volume.')
            
            request_data = {
                "Name":name,
                "RAIDType":raidlevel,
                "Links":{
                    "Drives":[
                        {'@odata.id': f'/redfish/v1/Systems/1/Storage/{cid}/Drives/{did}'} for did in spec_disks]}}
            if spec_hotspares:
                request_data["Links"]["DedicatedSpareDrives"] = {[
                    {'@odata.id': f'/redfish/v1/Systems/1/Storage/{cid}/Drives/{hid}' for hid in spec_hotspares}]}
            if volsize:
                request_data["CapacityBytes"] = volsize
            if stripsize:
                request_data["StripSizeBytes"] = stripsize
            if read_policy:
                request_data["ReadCachePolicy"] = read_policy
            if write_policy:
                request_data["WriteCachePolicy"] = write_policy
            
            msg, code=self.webclient.grab_json_response_with_status(
                f'/redfish/v1/Systems/1/Storage/{cid}/Volumes',
                method='POST',
                data=request_data)
            if code == 500 and not stripsize:
                    # Mystery error can be a mandatory strip size, default to 64k to match WebUI behavior
                    request_data["StripSizeBytes"] = 65536
                    msg, code=self.webclient.grab_json_response_with_status(
                        f'/redfish/v1/Systems/1/Storage/{cid}/Volumes',
                        method='POST',
                        data=request_data)
            if code == 500:
                raise Exception("Unexpected response to volume creation: " + repr(msg))
            await asyncio.sleep(60)
            #Even if in web the volume appears immediately, get_storage_configuration does not see it that fast
            newcfg = await self.get_storage_configuration(False)
            newvols = [v.id for p in newcfg.arrays for v in p.volumes]
            currvols = [v.id for p in currcfg.arrays for v in p.volumes]
            newvol = list(set(newvols) - set(currvols))[0]
            if default_init:
                msg, code = await self.webclient.grab_json_response_with_status(
                    f'/redfish/v1/Systems/1/Storage/{cid}/Volumes/{newvol[1]}/Actions/Volume.Initialize',
                    method='POST',
                    data = {"InitializeType": default_init})
                if code == 500:
                    raise Exception("Unexpected response to volume initialization: " + repr(msg))

    async def attach_remote_media(self, url, user, password, vmurls):
        for vmurl in vmurls:
            if 'EXT' not in vmurl:
                continue
            vminfo = await self._do_web_request(vmurl, cache=False)
            if vminfo['ConnectedVia'] != 'NotConnected':
                continue
            msg,code = await self.webclient.grab_json_response_with_status(
                vmurl,
                data={'Image': url, 'Inserted': True},
                method='PATCH')
            if code == 500:
                errmsg = "Unexpected response when attaching remote media: " + repr(msg)
                try:
                    if url.startswith('https://'):
                        dmsg = json.loads(msg.decode('utf-8'))
                        if dmsg.get('error', {}).get('code', '') == 'Base.1.16.0.InternalError':
                            errmsg = 'XCC3 reported an internal error while attaching https media, check the certificate authorities on the XCC3'
                except Exception:
                    pass
                raise Exception(errmsg)
            self._invalidate_url_cache(vmurl)                
            raise pygexc.BypassGenericBehavior()
            break
        else:
            raise pygexc.InvalidParameterValue(
                'XCC does not have required license for operation')

    async def supports_expand(self, url):
        return True

    async def get_screenshot(self, outfile):
        wc = self.webclient.dupe()
        await self._get_session_token(wc)
        url = '/web_download/Mini_ScreenShot.jpg'
        fd = webclient.make_downloader(wc, url, outfile)
        await fd.join()

    async def get_diagnostic_data(self, savefile, progress=None, autosuffix=False):
        try:
            tsk = await self._do_web_request(
                '/redfish/v1/Systems/1/LogServices/DiagnosticLog/Actions/LogService.CollectDiagnosticData',
                {"DiagnosticDataType": "Manager", "SelectDataTypes": ["adapter","worknote","thermal"]})
        except pygexc.RedfishError:
            tsk = await self._do_web_request(
                '/redfish/v1/Systems/1/LogServices/DiagnosticLog/Actions/LogService.CollectDiagnosticData',
                {"DiagnosticDataType": "Manager", "SelectDataTypes": ["adapter"]})

        taskrunning = True
        taskurl = tsk.get('TaskMonitor', None)
        pct = 0 if taskurl else 100
        durl = None
        while pct < 100 and taskrunning:
            status = await self._do_web_request(taskurl)
            durl = status.get('AdditionalDataURI', '')
            pct = status.get('PercentComplete', 0)
            taskrunning = status.get('TaskState', 'Complete') == 'Running'
            if progress:
                progress({'phase': 'initializing', 'progress': float(pct)})
            if taskrunning:
                await asyncio.sleep(3)
        if not durl:
            raise Exception("Failed getting service data url")
        fname = os.path.basename(durl)
        if autosuffix and not savefile.endswith('.tar.zst'):
            savefile += '-{0}'.format(fname)
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

    async def get_ikvm_methods(self):
        return ['openbmc', 'url']

    async def get_ikvm_launchdata(self):
        access = await self._do_web_request('/redfish/v1/Managers/1/Oem/Lenovo/RemoteControl/Actions/LenovoRemoteControlService.GetRemoteConsoleToken', {})
        if access.get('Token', None):
            accessinfo = {
                'url': '/#/login?{}&context=remote&mode=multi'.format(access['Token'])
                }
            return accessinfo

    async def get_system_power_watts(self, fishclient):
        powerinfo = await fishclient._do_web_request('/redfish/v1/Chassis/1/Sensors/power_Sys_Power')
        return powerinfo['Reading']
    
    async def get_health(self, fishclient, verbose=True):
        rsp = await self._do_web_request('/api/providers/imm_active_events')
        summary = {'badreadings': [], 'health': pygconst.Health.Ok}
        fallbackdata = []
        hmap = {
            0 : pygconst.Health.Ok,
            3: pygconst.Health.Critical,
            2: pygconst.Health.Warning,
        }
        infoevents = False
        existingevts = set([])
        for item in rsp.get('items', ()):
            # while usually the ipmi interrogation shall explain things,
            # just in case there is a gap, make sure at least the
            # health field is accurately updated
            itemseverity = hmap.get(item.get('Severity', 2),
                                    pygconst.Health.Critical)
            if itemseverity == pygconst.Health.Ok:
                infoevents = True
                continue
            if (summary['health'] < itemseverity):
                summary['health'] = itemseverity
            evtsrc = item.get('Oem', {}).get('Lenovo', {}).get('Source', '')
            currevt = '{}:{}'.format(evtsrc, item['Message'])
            if currevt in existingevts:
                continue
            existingevts.add(currevt)
            fallbackdata.append(SensorReading({
                'name': evtsrc,
                'states': [item['Message']],
                'health': itemseverity,
                'type': evtsrc,
            }, ''))
        summary['badreadings'] = fallbackdata
        return summary   

    async def _get_cpu_temps(self, fishclient):
        cputemps = []
        for reading in await super()._get_cpu_temps(fishclient):
            if 'Margin' in reading['Name']:
                continue
            cputemps.append(reading)
        return cputemps

    async def get_system_configuration(self, hideadvanced=True, fishclient=None):
        stgs = (await self._getsyscfg(fishclient))[0]
        outstgs = {}
        for stg in stgs:
            outstgs[f'UEFI.{stg}'] = stgs[stg]
        return outstgs

    async def set_system_configuration(self, changeset, fishclient):
        bmchangeset = {}
        vpdchangeset = {}
        for stg in list(changeset):
            if stg.startswith('BMC.'):
                bmchangeset[stg.replace('BMC.', '')] = changeset[stg]
                del changeset[stg]
            if stg.startswith('UEFI.'):
                changeset[stg.replace('UEFI.', '')] = changeset[stg]
                del changeset[stg]
            if stg.startswith('VPD.'):
                vpdchangeset[stg.replace('VPD.', '')] = changeset[stg]
                del changeset[stg]
        if changeset:
            await super().set_system_configuration(changeset, fishclient)
        if bmchangeset:
            await self._set_xcc3_settings(bmchangeset, fishclient)
        if vpdchangeset:
            await self._set_xcc3_vpd(vpdchangeset, fishclient)

    async def _set_xcc3_vpd(self, changeset, fishclient):
        newvpd = {'Attributes': changeset}
        await fishclient._do_web_request(
            '/redfish/v1/Chassis/1/Oem/Lenovo/SysvpdSettings/Actions/LenovoSysVpdSettings.SetVpdSettings',
            newvpd)


    async def _set_xcc3_settings(self, changeset, fishclient):
        currsettings, reginfo = await self._get_lnv_bmcstgs(fishclient)
        rawsettings = await fishclient._do_web_request('/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings',
                                                 cache=False)
        rawsettings = rawsettings.get('Attributes', {})
        pendingsettings = {}
        ret = self._set_redfish_settings(
            changeset, fishclient, currsettings, rawsettings,
            pendingsettings, self.lenovobmcattrdeps, reginfo,
            '/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings')
        await fishclient._do_web_request('/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings', cache=False)
        return ret

    oemacctmap = {
        'password_reuse_count': 'MinimumPasswordReuseCycle',
        'password_change_interval':  'MinimumPasswordChangeIntervalHours',
        'password_expiration': 'PasswordExpirationPeriodDays',
        'password_complexity': 'ComplexPassword',
        }

    acctmap = {
        'password_login_failures': 'AccountLockoutThreshold',
        'password_min_length': 'MinPasswordLength',
        'password_lockout_period': 'AccountLockoutDuration',
        }

    async def update_firmware(self, filename, data=None, progress=None, bank=None, otherfields=()):
        if not otherfields and bank == 'backup':
            uxzcount = 0
            otherfields = {'UpdateParameters': {"Targets": ["/redfish/v1/UpdateService/FirmwareInventory/BMC-Backup"]}}
            needseek = False
            if data and hasattr(data, 'read'):
                if zipfile.is_zipfile(data):
                    needseek = True
                    z = zipfile.ZipFile(data)
                else:
                    data.seek(0)
            elif data is None and zipfile.is_zipfile(filename):
                z = zipfile.ZipFile(filename)
            if z:
                for tmpname in z.namelist():
                    if tmpname.startswith('payloads/'):
                        uxzcount += 1
                        if tmpname.endswith('.uxz'):
                            wrappedfilename = tmpname
            if uxzcount == 1 and wrappedfilename:
                filename = os.path.basename(wrappedfilename)
                data = z.open(wrappedfilename)
            elif needseek:
                data.seek(0)
        await super().update_firmware(filename, data=data, progress=progress, bank=bank, otherfields=otherfields)


    async def get_bmc_configuration(self):
        settings = {}
        acctsrv = await self._do_web_request('/redfish/v1/AccountService')
        for oemstg in self.oemacctmap:
            settings[oemstg] = {
                'value': acctsrv['Oem']['Lenovo'][self.oemacctmap[oemstg]]}
        for stg in self.acctmap:
            settings[stg] = {
                'value': acctsrv[self.acctmap[stg]]}
        bmcstgs = await self._do_web_request('/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings')
        bmcattrs = bmcstgs['Attributes']
        self.ethoverusb = True if 'EthOverUSBEnabled' in bmcattrs else False
        usbcfg = bmcattrs.get('NetMgrUsb0Enabled', bmcattrs.get('EthOverUSBEnabled', 'False'))
        usbeth = 'Enable' if usbcfg == 'True' else 'Disable'
        settings['usb_ethernet'] = {
            'value': usbeth
        }
        usbcfg = bmcattrs.get('NetMgrUsb0PortForwardingEnabled', bmcattrs.get('EthOverUSBPortForwardingEnabled', 'False'))
        fwd = 'Enable' if usbcfg == 'True' else 'Disable'
        settings['usb_ethernet_port_forwarding'] = fwd
        mappings = []
        for idx in range(1, 11):
            keyname = 'NetMgrUsb0PortForwardingPortMapping.{}'.format(idx)
            keyaltname = 'EthOverUSBPortForwardingPortMapping_{}'.format(idx)
            currval = bmcattrs.get(keyname, bmcattrs.get(keyaltname, '0,0'))
            if currval == '0,0':
                continue
            src, dst = currval.split(',')
            mappings.append('{}:{}'.format(src,dst))
        settings['usb_forwarded_ports'] = {'value': ','.join(mappings)}
        cfgin = (await self._get_lnv_bmcstgs(self))[0]
        for stgname in cfgin:
            settings[f'{stgname}'] = cfgin[stgname]        
        return settings

    async def set_bmc_configuration(self, changeset):
        acctattribs = {}
        usbsettings = {}
        bmchangeset = {}
        rawchangeset = {}
        for key in changeset:
            rawchangeset[key] = changeset[key]
            if isinstance(changeset[key], str):
                changeset[key] = {'value': changeset[key]}
            currval = changeset[key].get('value', None)
            if key == 'password_complexity':
                if currval.lower() in ("false", 0):
                    currval = False
                elif currval.lower() in ('true', 1):
                    currval = True
            elif key.lower().startswith('usb_'):
                if 'forwarded_ports' not in key.lower():
                    currval = currval.lower()
                    if currval and 'disabled'.startswith(currval):
                        currval = 'False'
                    elif currval and 'enabled'.startswith(currval):
                        currval = 'True'
            else:
                try:
                    currval = int(currval)
                except ValueError:
                    pass
            if key.lower() in self.oemacctmap:
                if 'Oem' not in acctattribs:
                    acctattribs['Oem'] = {'Lenovo': {}}
                acctattribs['Oem']['Lenovo'][
                    self.oemacctmap[key.lower()]] = currval
                if key.lower() == 'password_expiration':
                    warntime = int(int(currval) * 0.08)
                    acctattribs['Oem']['Lenovo'][
                        'PasswordExpirationWarningPeriod'] = warntime
            elif key.lower() in self.acctmap:
                acctattribs[self.acctmap[key.lower()]] = currval
            elif key.lower() in (
                    'usb_ethernet', 'usb_ethernet_port_forwarding',
                    'usb_forwarded_ports'):
                usbsettings[key] = currval
            else:
                bmchangeset[key.replace('bmc.', '')] = rawchangeset[key]
        if acctattribs:
            await self._do_web_request(
                '/redfish/v1/AccountService', acctattribs, method='PATCH')
            await self._do_web_request('/redfish/v1/AccountService', cache=False)
        if usbsettings:
            await self.apply_usb_configuration(usbsettings)
        if bmchangeset:
            self._set_xcc3_settings(bmchangeset, self)        

    async def apply_usb_configuration(self, usbsettings):
        bmcattribs = {}
        if not hasattr(self, 'ethoverusb'):
            await self.get_bmc_configuration()
        if 'usb_forwarded_ports' in usbsettings:
            pairs = usbsettings['usb_forwarded_ports'].split(',')
            idx = 1
            for pair in pairs:
                if self.ethoverusb:
                    keyname = 'EthOverUSBPortForwardingPortMapping_{}'.format(idx)
                else:
                    keyname = 'NetMgrUsb0PortForwardingPortMapping.{}'.format(idx)
                pair = pair.replace(':', ',')
                if self.ethoverusb:
                    keyname = 'EthOverUSBPortForwardingPortMapping_{}'.format(idx)
                else:
                    keyname = 'NetMgrUsb0PortForwardingPortMapping.{}'.format(idx)
                bmcattribs[keyname] = '0,0'
                idx += 1
            while idx < 11:
                bmcattribs[
                    'NetMgrUsb0PortForwardingPortMapping.{}'.format(
                        idx)] = '0,0'
                idx += 1
        if 'usb_ethernet' in usbsettings:
            keyname = 'EthOverUSBEnabled' if self.ethoverusb else 'NetMgrUsb0Enabled'
            bmcattribs[keyname] = usbsettings['usb_ethernet']
        if 'usb_ethernet_port_forwarding' in usbsettings:
            keyname = 'EthOverUSBPortForwardingEnabled' if self.ethoverusb else 'NetMgrUsb0PortForwardingEnabled'
            bmcattribs[keyname] = usbsettings[
                    'usb_ethernet_port_forwarding']
        await self._do_web_request(
            '/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings',
            {'Attributes': bmcattribs}, method='PATCH')
        await self._do_web_request(
            '/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings', cache=False)

    async def get_extended_bmc_configuration(self, fishclient, hideadvanced=True):
        cfgin = (await self._get_lnv_bmcstgs(fishclient))[0]
        cfgout = {}
        for stgname in cfgin:
            cfgout[f'BMC.{stgname}'] = cfgin[stgname]
        vpdin = (await self._get_lnv_vpd(fishclient))[0]
        for stgname in vpdin:
            cfgout[f'VPD.{stgname}'] = vpdin[stgname]
        return cfgout

    async def _get_lnv_vpd(self, fishclient):
        currsettings, reginfo = await self._get_lnv_stgs(
            fishclient, '/redfish/v1/Chassis/1/Oem/Lenovo/SysvpdSettings')
        self.lenovobmcattrdeps = reginfo[3]
        return currsettings, reginfo

    async def _get_lnv_bmcstgs(self, fishclient):
        currsettings, reginfo = await self._get_lnv_stgs(
            fishclient, '/redfish/v1/Managers/1/Oem/Lenovo/BMCSettings')
        self.lenovobmcattrdeps = reginfo[3]
        return currsettings, reginfo

    async def _get_lnv_stgs(self, fishclient, url):
        bmcstgs = await fishclient._do_web_request(url)
        bmcreg = bmcstgs.get('AttributeRegistry', None)
        extrainfo = {}
        valtodisplay = {}
        currsettings = {}
        reginfo = {}, {}, {}, {}
        if bmcreg:
            reginfo = await self._get_attrib_registry(fishclient, bmcreg)
            if reginfo:
                extrainfo, valtodisplay, _, _ = reginfo
        for setting in bmcstgs.get('Attributes', {}):
            val = bmcstgs['Attributes'][setting]
            currval = val
            val = valtodisplay.get(setting, {}).get(val, val)
            val = {'value': val}
            val.update(**extrainfo.get(setting, {}))
            currsettings[setting] = val
        return currsettings, reginfo

    async def get_description(self, fishclient):
        rsp = await self._get_expanded_data('/redfish/v1/Chassis')
        for chassis in rsp['Members']:
            if (chassis['@odata.id'] == '/redfish/v1/Chassis/1'
                    and chassis['ChassisType'] != 'Blade'):
                hmm = chassis.get('HeightMm', None)
                if hmm:
                    return {'height': hmm/44.45}
            if (chassis['@odata.id'] == '/redfish/v1/Chassis/Enclosure'
                    and chassis.get('ChassisType', None) == 'Enclosure'):
                try:
                    slot = chassis['Location']['PartLocation']['LocationOrdinalValue']
                    slotnum = (2 * (slot >> 4) - 1) + ((slot & 15) % 10)
                    slotcoord = [slot >> 4, (slot & 15) - 9]
                    return {'slot': slotnum, 'slotlabel': '{:02x}'.format(slot), 'slotcoord': slotcoord}
                except KeyError:
                    continue
        return {}

    async def upload_media(self, filename, progress=None, data=None):
        wc = self.webclient
        uploadthread = await webclient.make_uploader(
            wc, '/rdoc_upload', filename, data,
            formname='file',
            formwrap=True)
        while not uploadthread.completed():
            try:
                await uploadthread.join(3)
            except asyncio.TimeoutError:
                pass
            if progress:
                progress({'phase': 'upload',
                          'progress': 100 * await uploadthread.get_progress()})
        rspstatus, rsp, headers = uploadthread.get_response()
        if rsp['return'] != 0:
            raise Exception('Issue uploading file')
        remfilename = rsp['upload_filename']
        if progress:
            progress({'phase': 'upload',
                      'progress': 100.0})
        await self._do_web_request(
            '/redfish/v1/Systems/1/VirtualMedia/RDOC1',
            {'Image':'file:///gpx/rdocupload/' + remfilename,
             'WriteProtected': False}, method='PATCH')
        if progress:
            progress({'phase': 'complete'})

    async def get_firmware_inventory(self, components, fishclient, category):
        sfs = await fishclient._do_web_request('/api/providers/system_firmware_status')
        pendingscm = sfs.get('fpga_scm_pending_build', None)
        pendinghpm = sfs.get('fpga_hpm_pending_build', None)
        if pendingscm == '*':
            pendingscm = None
        if pendinghpm == '*':
            pendinghpm = None    
        oldtimeout = fishclient.wc.get_timeout()
        fishclient.wc.set_timeout(120)
        fwinv = await fishclient.get_fwinventory()
        fwlist = await fishclient._do_web_request(fwinv + '?$expand=.')
        fishclient.wc.set_timeout(oldtimeout)
        fwlist = copy.deepcopy(fwlist.get('Members', []))
        self._fwnamemap = {}
        for redres in fwlist:
            fwurl = redres['@odata.id']
            res = (redres, fwurl)
            if fwurl.startswith('/redfish/v1/UpdateService/FirmwareInventory/Bundle.'):
                continue  # skip Bundle information for now
            if redres.get('Name', '').startswith('Firmware:'):
                redres['Name'] = redres['Name'].replace('Firmware:', '')
            if redres['Name'].startswith('Firmware-PSoC') and 'Drive_Backplane' in redres["@odata.id"]:
                redres['Name'] = 'Drive Backplane'
            if redres['Name'].startswith('DEVICE-'):
                redres['Name'] = redres['Name'].replace('DEVICE-', '')
            if redres['Name'].startswith('POWER-PSU'):
                redres['Name'] = redres['Name'].replace('POWER-', '')
            swid = redres.get('SoftwareId', '')
            buildid = ''
            version = redres.get('Version', None)
            for prefix in ['FPGA-', 'UEFI-', 'BMC-', 'LXPM-', 'DRVWN-', 'DRVLN-', 'LXUM']:
                if swid.startswith(prefix):
                    buildid = swid.split('-')[1] + version.split('-')[0]
                    version = '-'.join(version.split('-')[1:])
                    break
            if version:
                redres['Version'] = version
            cres = fishclient._extract_fwinfo(res)
            if cres[0] is None:
                continue
            if buildid:
                cres[1]['build'] = buildid
            yield cres
            if cres[0] == 'SCM-FPGA' and pendingscm:
                yield 'SCM-FPGA Pending', {
                    'Name': 'SCM-FPGA Pending',
                    'build': pendingscm}
            elif cres[0] == 'HPM-FPGA' and pendinghpm:
                yield 'HPM-FPGA Pending', {
                    'Name': 'HPM-FPGA Pending',
                    'build': pendinghpm}
        raise pygexc.BypassGenericBehavior()


