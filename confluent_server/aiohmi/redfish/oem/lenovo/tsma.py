# Copyright 2015-2017 Lenovo
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
import os
import struct
import time
try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode


import aiohmi.exceptions as exc
import aiohmi.media as media
import aiohmi.redfish.oem.generic as generic
import aiohmi.util.webclient as webclient

hpm_by_filename = {}


class HpmSection(object):
    __slots__ = ['comp_id', 'comp_ver', 'comp_name', 'section_flash', 'data',
                 'hash_size', 'combo_image']


def cstr_to_str(cstr):
    try:
        endidx = cstr.index(b'\x00')
        cstr = cstr[:endidx]
    except Exception:
        pass
    if not isinstance(cstr, str):
        cstr = cstr.decode('utf8')
    return cstr


def read_hpm(filename, data):
    hpminfo = []
    if data:
        hpmfile = data
        hpmfile.seek(0)
    else:
        hpmfile = open(filename, 'rb')
    try:
        hpmfile.seek(0x20)
        skip = struct.unpack('>H', hpmfile.read(2))[0]
        hpmfile.seek(skip + 1, 1)
        sectype, compid = struct.unpack('BB', hpmfile.read(2))
        while sectype == 2:
            currsec = HpmSection()
            currsec.comp_id = compid
            hpmfile.seek(1, 1)
            major, minor, pat = struct.unpack('<BBI', hpmfile.read(6))
            currsec.comp_ver = '{0}.{1}.{2}'.format(major, minor, pat)
            currsec.comp_name = hpmfile.read(21).rstrip(b'\x00')
            currlen = struct.unpack('<I', hpmfile.read(4))[0] - 16
            oemstr = hpmfile.read(4)
            if oemstr != b'OEM\x00':
                raise Exception(
                    'Unrecognized HPM field near {0}'.format(hpmfile.tell()))
            currsec.section_flash = struct.unpack('<I', hpmfile.read(4))[0]
            hashpresent, hdrsize, blocks = struct.unpack('BBB',
                                                         hpmfile.read(3))
            if hashpresent != 1:
                hashpresent = 0
            currsec.hash_size = hashpresent * (256 * blocks + hdrsize)
            hpmfile.seek(5, 1)
            currsec.data = hpmfile.read(currlen)
            hpminfo.append(currsec)
            sectype, compid = struct.unpack('BB', hpmfile.read(2))
        upimg = (hpminfo[1].data[:-hpminfo[1].hash_size]
                 + hpminfo[2].data[:-hpminfo[2].hash_size])
        hpminfo[2].combo_image = upimg
        hpminfo[1].combo_image = upimg
        currpos = hpmfile.tell()
        hpmfile.seek(0, 2)
        endpos = hpmfile.tell()
        if currpos < (endpos - 512):
            raise Exception("Unexpected end of HPM file")
    finally:
        if not data:
            hpmfile.close()
    return hpminfo


class TsmHandler(generic.OEMHandler):
    hostnic = 'usb0'

    @classmethod
    async def create(cls, sysinfo, sysurl, webclient, cache=None, fish=None,
                 gpool=None):
        self = await super(TsmHandler, cls).create(sysinfo, sysurl, webclient, cache, fish,
                                         gpool)
        if cache is None:
            cache = {}
        self._wc = None
        self.username = None
        self.password = None
        self.csrftok = None
        self.isipmi = bool(fish)
        self.fish = fish
        self.fishclient = None
        self.tsm = webclient.thehost
        self._certverify = webclient.verifycallback
        return self

    async def clear_bmc_configuration(self):
        wc = await self.get_wc()
        rsp, status = await wc.grab_json_response_with_status(
                '/api/maintenance/restore_defaults',
                {"id": 1,
                 "sdr": 0,
                 "fru": 1,
                 "sel": 1,
                 "ipmi": 1,
                 "network": 1,
                 "ntp": 1,
                 "snmp": 1,
                 "ssh": 1,
                 "kvm": 1,
                 "authentication": 1,
                 "syslog": 0,
                 "web": 1,
                 "extlog": 0,
                 "redfish": 1},
                method='PUT')

    async def get_bmc_configuration(self):
        wc = await self.get_wc()
        rsp, status = await wc.grab_json_response_with_status(
            '/api/settings/dns-info')
        if status != 200:
            raise Exception(repr(rsp))
        settings = {}
        settings['dns_domain'] = {
            'value': rsp['domain_name']
        }
        dnssrvs = []
        for idx in range(3):
            currsrv = rsp.get('dns_server{0}'.format(idx + 1), '::')
            if currsrv and currsrv != '::':
                dnssrvs.append(currsrv)
        settings['dns_servers'] = {'value': ','.join(dnssrvs)}
        rsp, status = await wc.grab_json_response_with_status(
            '/api/LockoutPolicystatus')
        if status == 200:
            isenabled = rsp.get('Status', 0) == 1
            if isenabled:
                settings['password_login_failures'] = {'value': rsp.get(
                    'Attemptstimes', 0)}
            else:
                settings['password_login_failures'] = {'value': 0}
        rsp, status = await wc.grab_json_response_with_status(
            '/api/GetPWComplex')
        if status == 200:
            settings['password_complexity'] = {'value': rsp.get(
                'pw_complex', 0)}
        return settings

    async def set_bmc_configuration(self, changeset):
        dnschgs = {}
        wc = await self.get_wc()
        for key in changeset:
            if isinstance(changeset[key], str):
                changeset[key] = {'value': changeset[key]}
            currval = changeset[key].get('value', None)
            if 'dns_servers'.startswith(key.lower()):
                srvs = currval.split(',')
                for idx in range(3):
                    if idx < len(srvs):
                        dnschgs['dns_server{0}'.format(idx + 1)] = srvs[idx]
                    else:
                        dnschgs['dns_server{0}'.format(idx + 1)] = ''
            if 'dns_domain'.startswith(key.lower()):
                dnschgs['domain_name'] = currval
            if 'password_complexity'.startswith(key.lower()):
                self._set_pass_complexity(currval, wc)
            if 'password_login_failures'.startswith(key.lower()):
                await self._set_pass_lockout(currval, wc)
        if dnschgs:
            await self._set_dns_config(dnschgs, wc)

    async def _set_pass_complexity(self, currval, wc):
        rsp, status = await wc.grab_json_response_with_status(
            '/api/SetPWComplex', {'Enable': currval})
        if status != 200:
            raise Exception(repr(rsp))

    async def _set_pass_lockout(self, currval, wc):
        rsp, status = await wc.grab_json_response_with_status(
            '/api/LockoutPolicystatus')
        if status != 200:
            raise Exception(repr(rsp))
        request = {
            'SameStatus': 0,
            'Lock_min': rsp.get('Locktime', 5),
            'Rest_min': rsp.get('Resettime', 1),
            'Attemptstimes': rsp.get('Attemptstimes', 3)
        }
        if currval == 0:
            request['Enable'] = 0
        else:
            request['Enable'] = 1
            request['Attemptstimes'] = currval
        rsp, status = await wc.grab_json_response_with_status(
            '/api/SetLockoutPolicy', request)
        if status != 200:
            raise Exception(repr(rsp))

    async def _set_dns_config(self, dnschgs, wc):
        rsp, status = await wc.grab_json_response_with_status(
            '/api/settings/dns-info')
        if status != 200:
            raise Exception(repr(rsp))
        rsp['domain_manual'] = 1
        for i in range(3):
            keyn = 'dns_server{0}'.format(i + 1)
            if rsp[keyn] == '::':
                rsp[keyn] = ''
        for chg in dnschgs:
            rsp[chg] = dnschgs[chg]
        rsp, status = await wc.grab_json_response_with_status(
            '/api/settings/dns-info', rsp, method='PUT')
        if status != 200:
            raise Exception(repr(rsp))
        rsp, status = await wc.grab_json_response_with_status(
            '/api/settings/dns/restart', {'dns_status': 1}, method='PUT')
        if status != 200:
            raise Exception(repr(rsp))

    async def clear_uefi_configuration(self):
        if not self.fishclient:
            await self.init_redfish()
        return await self.fishclient.clear_system_configuration()

    async def get_uefi_configuration(self, hideadvanced=True):
        if not self.fishclient:
            await self.init_redfish()
        return await self.fishclient.get_system_configuration(hideadvanced)

    async def set_uefi_configuration(self, changeset):
        if not self.fishclient:
            await self.init_redfish()
        return await self.fishclient.set_system_configuration(changeset)

    async def get_diagnostic_data(self, savefile, progress=None, autosuffix=False):
        wc = await self.get_wc()
        await wc.grab_json_response('/api/mini_ffdc', {'action': 'trigger'})
        status = 1
        percent = 0
        while status == 1:
            await asyncio.sleep(5)
            check = await wc.grab_json_response('/api/mini_ffdc',
                                          {'action': 'check'})
            status = check.get('status', -1)
            if progress:
                progress({'phase': 'initializing', 'progress': float(percent)})
            percent += 1
        if status != 2:
            raise Exception(
                "Unknown error generating service data: " + repr(check))
        if autosuffix and not savefile.endswith('.tar'):
            savefile += '.tar'
        fd = webclient.make_downloader(wc, '/api/mini_ffdc/package', savefile)
        while not fd.completed():
            try:
                await fd.join(1)
            except asyncio.TimeoutError:
                pass
            if progress:
                currprog = await fd.get_progress()
                if currprog:
                    progress({'phase': 'download',
                              'progress': 100 * currprog})
        if fd.exc:
            raise fd.exc
        if progress:
            progress({'phase': 'complete'})
        return savefile

    async def init_redfish(self):
        self.fishclient = await self.fish.Command.create(
            self.tsm, self.username, self.password,
            verifycallback=self._certverify)

    async def get_ntp_enabled(self):
        wc = await self.get_wc()
        rsp, status = await wc.grab_json_response_with_status(
            '/api/settings/date-time')
        if status != 200:
            raise Exception(repr(rsp))
        return rsp.get('ntp_auto_date', 0) > 0

    async def set_ntp_enabled(self, enabled):
        wc = await self.get_wc()
        rsp, status = await wc.grab_json_response_with_status(
            '/api/settings/date-time')
        if status != 200:
            raise Exception(repr(rsp))
        rsp['ntp_auto_date'] = 1 if enabled else 0
        rsp, status = await wc.grab_json_response_with_status(
            '/api/settings/date-time', rsp, method='PUT')
        if status != 200:
            raise Exception(repr(rsp))

    async def get_ntp_servers(self):
        wc = await self.get_wc()
        rsp, status = await wc.grab_json_response_with_status(
            '/api/settings/date-time')
        if status != 200:
            raise Exception(repr(rsp))
        srvs = []
        pntp = rsp.get('primary_ntp', None)
        if pntp:
            srvs.append(pntp)
        pntp = rsp.get('secondary_ntp', None)
        if pntp:
            srvs.append(pntp)
        return srvs

    async def set_ntp_server(self, server, index=0):
        wc = await self.get_wc()
        rsp, status = await wc.grab_json_response_with_status(
            '/api/settings/date-time')
        if status != 200:
            raise Exception(repr(rsp))
        if index == 0:
            rsp['primary_ntp'] = server
        elif index == 1:
            rsp['secondary_ntp'] = server
        rsp['ntp_auto_date'] = 1
        rsp, status = await wc.grab_json_response_with_status(
            '/api/settings/date-time', rsp, method='PUT')
        if status != 200:
            raise Exception(repr(rsp))

    async def get_firmware_inventory(self, components, raisebypass=True,
                               ipmicmd=None):
        wc = await self.get_wc()
        fwinf, status = await wc.grab_json_response_with_status(
            '/api/DeviceVersion')
        gotinfo = False
        if status < 200 or status >= 300:
            raise Exception('Error connecting to HTTP API')
        for biosinf in fwinf:
            if biosinf.get('device', None) != 1:
                continue
            if not biosinf.get('buildname', False):
                break
            biosres = {
                'build': biosinf['buildname']
            }
            if biosinf.get('main', False):
                biosres['version'] = '{0}.{1}'.format(
                    biosinf['main'][0], biosinf['main'][1:])
            yield ('UEFI', biosres)
            gotinfo = True
            break
        for lxpminf in fwinf:
            if lxpminf.get('device', None) != 2:
                continue
            if not lxpminf.get('buildname', False):
                break
            lxpmres = {
                'build': lxpminf['buildname']
            }
            if lxpminf.get('main', False):
                subver = lxpminf.get('sub', 0)
                lxpmres['version'] = '{0}.{1:02x}'.format(
                    lxpminf['main'], subver)
            yield ('LXPM', lxpmres)
        if ipmicmd:
            rsp = await ipmicmd.raw_command(0x3c, 0x40, data=(7, 2))
            buildid = cstr_to_str(bytes(rsp['data']))
            yield ('LXPM Windows Driver Bundle', {'build': buildid})
            rsp = await ipmicmd.raw_command(0x3c, 0x40, data=(7, 3))
            buildid = cstr_to_str(bytes(rsp['data']))
            yield ('LXPM Linux Driver Bundle', {'build': buildid})
        name = 'TSM'
        fwinf, status = await wc.grab_json_response_with_status('/api/get-sysfwinfo')
        if status != 200:
            raise Exception('Error {0} retrieving TSM version: {1}'.format(
                status, fwinf))
        for cinf in fwinf:
            if 'fw_ver' not in cinf:
                continue
            if cinf.get('buildname', None) == 'N/A':
                continue
            if '.' not in cinf['fw_ver']:
                continue
            bmcinf = {
                'version': cinf['fw_ver'],
                'build': cinf['buildname'],
                'date': cinf['builddate'],
            }
            yield (name, bmcinf)
            gotinfo = True
            name += ' Backup'
        if not gotinfo:
            raise Exception("Unable to retrieve firmware information")
        if raisebypass:
            raise exc.BypassGenericBehavior()

    async def get_wc(self):
        self.fwid = None
        if self._wc:
            rsp, status = await self._wc.grab_json_response_with_status(
                '/api/chassis-status')
            if status == 200:
                return self._wc
        authdata = {
            'username': self.username,
            'password': self.password,
        }
        wc = webclient.WebConnection(self.tsm, 443,
                                            verifycallback=self._certverify,
                                            timeout=180)
        wc.set_header('Content-Type', 'application/json')
        rsp, status = await wc.grab_json_response_with_status('/api/session',
                                                        authdata)
        if status == 403:
            wc.set_header('Content-Type', 'application/x-www-form-urlencoded')
            rsp, status = await wc.grab_json_response_with_status(
                '/api/session', urlencode(authdata))

        if status < 200 or status >= 300:
            raise Exception('Error establishing web session')
        self.csrftok = rsp['CSRFToken']
        wc.set_header('X-CSRFTOKEN', self.csrftok)
        self._wc = wc
        return wc

    async def update_firmware(self, filename, data=None, progress=None, bank=None, otherfields=None):
        wc = await self.get_wc()
        wc.set_header('Content-Type', 'application/json')
        basefilename = os.path.basename(filename)
        if filename.endswith('.hpm'):
            return await self.update_hpm_firmware(filename, progress, wc, data)
        elif 'uefi' in basefilename and filename.endswith('.rom'):
            return await self.update_sys_firmware(filename, progress, wc, data=data)
        elif 'amd-sas' in basefilename and filename.endswith('.bin'):
            return await self.update_sys_firmware(filename, progress, wc, data=data,
                                            type='bp')
        elif (('lxpm' in basefilename or 'fw_drv' in basefilename)
                and filename.endswith('.img')):
            return await self.update_lxpm_firmware(filename, progress, wc, data)
        else:
            raise Exception('Unsupported filename {0}'.format(filename))

    async def update_lxpm_firmware(self, filename, progress, wc, data):
        hdrs = wc.stdheaders.copy()
        hdrs['Content-Length'] = 0
        rsp = await wc.grab_json_response_with_status(
            '/api/maintenance/LXPMUploadMode',
            method='PUT', headers=hdrs)
        # name fwimage filname filename application/x-raw-disk-image...
        fu = await webclient.make_uploader(
            wc, '/api/maintenance/LXPMUpload',
            filename, data, formname='fwimage')
        while not fu.completed():
            try:
                await fu.join(3)
            except asyncio.TimeoutError:
                pass
            if progress:
                progress({
                    'phase': 'upload',
                    'progress': 100 * await fu.get_progress()})
        if progress:
            progress({
                'phase': 'apply',
                'progress': 0.0}
            )
        await wc.grab_json_response('/api/maintenance/LXPMImageSplit', {'type': 3})
        completion = False
        while not completion:
            rsp = await wc.grab_json_response('/api/maintenance/LXPMstatus')
            if rsp.get('state') == 0 and rsp.get('progress') == 4:
                break
        await wc.grab_json_response_with_status(
            '/api/maintenance/Outofflash', method='PUT', headers=hdrs)
        return 'complete'

    async def update_sys_firmware(self, filename, progress, wc, type='uefi',
                            data=None):
        if type == 'bp':
            rsp = await wc.grab_json_response_with_status('/api/chassis-status')
            if rsp[0]['power_status'] == 1:
                raise Exception("Cannot update BP firmware while system is on")
            updatemode = 'BPUploadMode'
            fileupload = 'BPfileUpload'
            startit = 'BPUpgradeStart'
            statusname = 'BPstatus'
        else:
            updatemode = 'flash'
            rsp = await wc.grab_json_response_with_status(
                '/api/maintenance/BIOSremoteSave',
                {"tftpip": "",
                 "tftpfile": ""}
            )
            fileupload = 'firmware/BIOS'
            startit = 'BIOSstart'
            statusname = 'BIOSstatus'
        hdrs = wc.stdheaders.copy()
        hdrs['Content-Length'] = 0
        rsp = await wc.grab_json_response_with_status(
            '/api/maintenance/{0}'.format(updatemode),
            method='PUT', headers=hdrs)
        fu = await webclient.make_uploader(
            wc, '/api/maintenance/{0}'.format(fileupload), filename, data,
            formname='fwimage')
        while not fu.completed():
            try:
                await fu.join(3)
            except asyncio.TimeoutError:
                pass
            if progress:
                progress({
                    'phase': 'upload',
                    'progress': 100 * await fu.get_progress()})
        if progress:
            progress({
                'phase': 'apply',
                'progress': 0.0}
            )
        rsp = await wc.grab_json_response_with_status(
            '/api/maintenance/{0}'.format(startit))
        applypct = 0.0
        if rsp[1] >= 200 and rsp[1] < 300 and rsp[0]['wRet'] == 0:
            updone = False
            while not updone:
                rsp = await wc.grab_json_response(
                    '/api/maintenance/{0}'.format(statusname))
                if rsp.get('state', 0) == 9:
                    break
                if rsp.get('state', 0) in (6, 10):
                    raise Exception('Update Failure')
                if (rsp.get('state', 0) == 8
                        and rsp.get('progress', 0) > 0 and progress):
                    progress({
                        'phase': 'apply',
                        'progress': 70 + float(rsp.get(
                            'progress', 0)) / 100 * 30})
                elif type == 'bp' and rsp.get('state', 0) == 1:
                    break
                elif progress and applypct < 70:
                    applypct += 1.4
                    progress({'phase': 'apply', 'progress': applypct})
            if type == 'bp':
                rsp = await wc.grab_json_response('/api/maintenance/BPfinish')
                hdrs = wc.stdheaders.copy()
                hdrs['Content-Length'] = 0
                rsp = await wc.grab_json_response_with_status(
                    '/api/maintenance/Outofflash', method='PUT', headers=hdrs)
                return 'complete'
            return 'pending'
        raise Exception('Update Failure')

    async def update_hpm_firmware(self, filename, progress, wc, data):
        rsp = await wc.grab_json_response('/api/maintenance/hpm/freemem')
        if 'MemFree' not in rsp:
            raise Exception('System Not Ready for update')
        if filename not in hpm_by_filename:
            hpminfo = read_hpm(filename, data)
            if len(hpminfo) != 3:
                raise Exception(
                    'This HPM update is currently not supported')
            hpm_by_filename[filename] = read_hpm(filename, data)
        else:
            hpminfo = hpm_by_filename[filename]
        rsp, status = await wc.grab_json_response_with_status(
            '/api/maintenance/hpm/updatemode', method='PUT')
        # first segment, make sure it is mmc,
        # then do the preparecomponents with the following payload
        if status != 200:
            raise Exception(rsp)
        uid = rsp['unique_id']
        self.fwid = uid
        payload = {
            'FWUPDATEID': uid,
            'COMPONENT_ID': 1,
            'COMPONENT_DATA_LEN': len(hpminfo[0].data),
            'IS_MMC': 1,
        }
        rsp, status = await wc.grab_json_response_with_status(
            '/api/maintenance/hpm/preparecomponents', payload, method='PUT')
        if status < 200 or status >= 300:
            await wc.grab_json_response_with_status(
                '/api/maintenance/hpm/exitupdatemode', {'FWUPDATEID': uid},
                method='PUT')
            raise Exception(rsp)
        fu = await webclient.make_uploader(
            wc, '/api/maintenance/hpm/mmcfw', 'blob', hpminfo[0].data, 'mmc')
        if progress:
            progress({'phase': 'upload', 'progress': 0.0})
        fu.start()
        while not fu.completed():
            try:
                await fu.join(3)
            except asyncio.TimeoutError:
                pass
            if progress:
                progress({
                    'phase': 'upload',
                    'progress': 50 * await fu.get_progress()})
        del payload['IS_MMC']
        payload['SECTION_FLASH'] = hpminfo[0].section_flash
        rsp, status = await wc.grab_json_response_with_status(
            '/api/maintenance/hpm/flash', payload, method='PUT')
        percent = 0
        while percent < 100:
            rsp, status = await wc.grab_json_response_with_status(
                '/api/maintenance/hpm/upgradestatus?COMPONENT_ID=1')
            if status < 200 or status >= 300:
                raise Exception(rsp)
            percent = rsp['PROGRESS']
            if progress:
                progress({
                    'phase': 'apply',
                    'progress': .5 * percent})
            if percent < 100:
                await asyncio.sleep(3)
        if progress:
            progress({'phase': 'validating', 'progress': 0.0})
        del payload['SECTION_FLASH']
        rsp, status = await wc.grab_json_response_with_status(
            '/api/maintenance/hpm/verifyimage', payload, method='PUT')
        percent = 0
        while percent < 100:
            rsp, status = await wc.grab_json_response_with_status(
                '/api/maintenance/hpm/verifyimagestatus?COMPONENT_ID=1')
            if status < 200 or status >= 300:
                raise Exception(rsp)
            percent = rsp['PROGRESS']
            if progress:
                progress({
                    'phase': 'validating',
                    'progress': 0.5 * percent})
            if percent < 100:
                await asyncio.sleep(3)
        rsp, status = await wc.grab_json_response_with_status(
            '/api/maintenance/hpm/exitupdatemode', {'FWUPDATEID': uid},
            method='PUT')
        fu = await webclient.make_uploader(wc, '/api/maintenance/firmware/firmware',
                                          'blob', hpminfo[1].combo_image, 'fwimage')
        fu.start()
        while not fu.completed():
            try:
                await fu.join(3)
            except asyncio.TimeoutError:
                pass
            if progress:
                progress({
                    'phase': 'upload',
                    'progress': 50 * await fu.get_progress() + 50})
        rsp = await wc.grab_json_response('/api/maintenance/firmware/verification')
        upgradeparms = {
            'preserve_config': 1,
            'flash_status': 1,
        }
        rsp, status = await wc.grab_json_response_with_status(
            '/api/maintenance/firmware/upgrade',
            upgradeparms, method='PUT')
        if progress:
            progress({'phase': 'apply', 'progress': 50.0})
        applied = False
        while not applied:
            rsp = await wc.grab_json_response(
                '/api/maintenance/firmware/flash-progress')
            percent = float(rsp['progress'].split('%')[0])
            percent = percent * 0.5 + 50
            if progress:
                progress({'phase': 'apply', 'progress': percent})
            if rsp['progress'] == '100% done' and rsp['state'] == 0:
                applied = True
                break
            await asyncio.sleep(3)
        hdrs = wc.stdheaders.copy()
        hdrs['Content-Length'] = 0
        rsp, status = await wc.grab_json_response_with_status(
            '/api/maintenance/reset', method='POST', headers=hdrs)
        self._wc = None
        return 'complete'

    async def _detach_all_media(self, wc, slots):
        for slot in slots:  # Stop all active redirections to reconfigure
            if slot['redirection_status'] != 0:
                await wc.grab_json_response(
                    '/api/settings/media/remote/stop-media',
                    {'image_name': slot['image_name'],
                     'image_type': slot['media_type'],
                     'image_index': slot['media_index']})

    async def detach_remote_media(self):
        wc = await self.get_wc()
        slots = await wc.grab_json_response(
            '/api/settings/media/remote/configurations')
        await self._detach_all_media(wc, slots)
        if not self.isipmi:
            raise exc.BypassGenericBehavior()

    async def _allocate_slot(self, slots, filetype, wc, server, path):
        currhdds = []
        currisos = []
        for slot in slots:
            if slot['image_name']:
                if slot['media_type'] == 1:
                    currisos.append(slot['image_name'])
                elif slot['media_type'] == 4:
                    currhdds.append(slot['image_name'])
                else:
                    raise exc.UnsupportedFunctionality(
                        'Unrecognized mounted image: ' + repr(slot))
        hddslots = len(currhdds)
        cdslots = len(currisos)
        if filetype == 1:
            cdslots += 1
        elif filetype == 4:
            hddslots += 1
        else:
            raise exc.UnsupportedFunctionality('Unknown slot type requested')
        gensettings = wc.grab_json_response('/api/settings/media/general')
        samesettings = gensettings['same_settings'] == 1
        if samesettings:
            hds = gensettings['cd_remote_server_address']
            hdp = gensettings['cd_remote_source_path'].replace('\\/', '/')
        else:
            hds = gensettings['hd_remote_server_address']
            hdp = gensettings['hd_remote_source_path'].replace('\\/', '/')
        if filetype == 1 and (currisos or (samesettings and currhdds)):
            if gensettings['cd_remote_server_address'] != server:
                raise exc.UnsupportedFunctionality(
                    'Cannot mount ISO images from multiple '
                    'servers at a time')
            if gensettings['cd_remote_source_path'].replace(
                    '\\/', '/') != path:
                raise exc.UnsupportedFunctionality(
                    'Cannot mount ISO images from different '
                    'directories at a time')
        if filetype == 4 and currhdds:
            if hds != server:
                raise exc.UnsupportedFunctionality(
                    'Cannot mount IMG images from multiple servers at a time')
            if hdp != path:
                raise exc.UnsupportedFunctionality(
                    'Cannot mount IMG images from muliple directories at a '
                    'time')
        await self._detach_all_media(wc, slots)
        if filetype == 1 or (samesettings and currhdds):
            gensettings['cd_remote_server_address'] = server
            gensettings['cd_remote_source_path'] = path
            gensettings['cd_remote_share_type'] = 'nfs'
            gensettings['mount_cd'] = 1
        elif filetype == 4:
            gensettings['same_settings'] = 0
            gensettings['hd_remote_server_address'] = server
            gensettings['hd_remote_source_path'] = path
            gensettings['hd_remote_share_type'] = 'nfs'
            gensettings['mount_hd'] = 1
        gensettings['remote_media_support'] = 1
        gensettings['cd_remote_password'] = ''
        gensettings['hd_remote_password'] = ''
        wc.grab_json_response_with_status('/api/settings/media/general',
                                          gensettings, method='PUT')
        # need to calibrate instances correctly
        currinfo, status = wc.grab_json_response_with_status(
            '/api/settings/media/instance')
        currinfo['num_cd'] = cdslots
        currinfo['num_hd'] = hddslots
        if currinfo['kvm_num_cd'] > cdslots:
            currinfo['kvm_num_cd'] = cdslots
        if currinfo['kvm_num_hd'] > hddslots:
            currinfo['kvm_num_hd'] = hddslots
        wc.grab_json_response_with_status(
            '/api/settings/media/instance', currinfo, method='PUT')
        images = wc.grab_json_response('/api/settings/media/remote/images')
        tries = 20
        while tries and not images:
            tries -= 1
            await asyncio.sleep(1)
            images = await wc.grab_json_response('/api/settings/media/remote/images')
        for iso in currisos:
            await self._exec_mount(iso, images, wc)
        for iso in currhdds:
            await self._exec_mount(iso, images, wc)

    async def _exec_mount(self, name, images, wc):
        for img in images:
            if img['image_name'] == name:
                break
        else:
            raise exc.InvalidParameterValue(
                'Unable to locate image {0}'.format(name))
        await wc.grab_json_response(
            '/api/settings/media/remote/start-media',
            {'image_name': name, 'image_type': img['image_type'],
             'image_index': img['image_index']})

    async def upload_media(self, filename, progress=None, data=None):
        raise exc.UnsupportedFunctionality(
            'Remote media upload not supported on this system')

    async def list_media(self, fishclient=None, cache=True):
        wc = await self.get_wc()
        rsp = await wc.grab_json_response('/api/settings/media/general')
        cds = rsp['cd_remote_server_address']
        cdpath = rsp['cd_remote_source_path']
        cdproto = rsp['cd_remote_share_type']
        if rsp['same_settings'] == 1:
            hds = cds
            hdpath = cdpath
            hdproto = cdproto
        else:
            hds = rsp['hd_remote_server_address']
            hdpath = rsp['hd_remote_source_path']
            hdproto = rsp['hd_remote_share_type']
        slots = await wc.grab_json_response(
            '/api/settings/media/remote/configurations')
        for slot in slots:
            if slot['redirection_status'] == 1:
                url = None
                if slot['media_type'] == 1:
                    url = '{0}://{1}{2}'.format(
                        cdproto, cds, cdpath)
                elif slot['media_type'] == 4:
                    url = '{0}://{1}{2}'.format(
                        hdproto, hds, hdpath)
                if url:
                    yield media.Media(slot['image_name'], url)

    async def attach_remote_media(self, url, user, password, vmurls):
        if not url.startswith('nfs://'):
            raise exc.UnsupportedFunctionality(
                'Only nfs:// urls are supported by this system')
        path = url.replace('nfs://', '')
        server, path = path.split('/', 1)
        path, filename = path.rsplit('/', 1)
        path = '/' + path
        filetype = filename.rsplit('.')[-1]
        if filetype == 'iso':
            filetype = 1
        elif filetype == 'img':
            filetype = 4
        else:
            raise exc.UnsupportedFunctionality(
                'Only iso and img files supported')
        wc = await self.get_wc()
        mountslots = await wc.grab_json_response(
            '/api/settings/media/remote/configurations')
        images = await wc.grab_json_response('/api/settings/media/remote/images')
        currtypeenabled = False
        for slot in mountslots:
            if slot['image_name'] == filename:
                return  # Already mounted...
        for img in images:
            if img['image_name'] == filename:
                break
            if img['image_type'] == filetype:
                currtypeenabled = True
        else:
            if currtypeenabled:
                raise exc.UnsupportedFunctionality(
                    'This system cannot mount images '
                    'from different locations at the same time')
            img = None
        for slot in mountslots:
            if slot['media_type'] != filetype:
                continue
            if slot['redirection_status'] == 0:
                break
        else:
            await self._allocate_slot(mountslots, filetype, wc, server, path)
        images = await wc.grab_json_response('/api/settings/media/remote/images')
        await self._exec_mount(filename, images, wc)
        if not self.isipmi:
            raise exc.BypassGenericBehavior()
