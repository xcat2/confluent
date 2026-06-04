# coding: utf8
# Copyright 2021 Lenovo
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

"""
The command module for redfish systems.  Provides https-only support
for redfish compliant endpoints
"""

import asyncio
import base64
from datetime import datetime
from datetime import timedelta
import json
import os
import re
import socket
import struct
import sys
import time

from dateutil import tz

import aiohmi.constants as const
import aiohmi.exceptions as exc
import aiohmi.redfish.oem.lookup as oem
from aiohmi.util.parse import parse_time
import aiohmi.util.webclient as webclient


numregex = re.compile('([0-9]+)')


powerstates = {
    'on': 'On',
    'off': 'ForceOff',
    'softoff': 'GracefulShutdown',
    'shutdown': 'GracefulShutdown',
    'reset': 'ForceRestart',
    'boot': None,
}


boot_devices_read = {
    'BiosSetup': 'setup',
    'Cd': 'optical',
    'Floppy': 'floppy',
    'Hdd': 'hd',
    'None': 'default',
    'Pxe': 'network',
    'Usb': 'usb',
    'SDCard': 'sdcard',
    'UefiHttp': 'http',
}


_healthmap = {
    'Critical': const.Health.Critical,
    'Unknown': const.Health.Warning,
    'Warning': const.Health.Warning,
    'OK': const.Health.Ok,
    None: const.Health.Ok,
}


def _mask_to_cidr(mask):
    maskn = socket.inet_pton(socket.AF_INET, mask)
    maskn = struct.unpack('!I', maskn)[0]
    cidr = 32
    while maskn & 0b1 == 0 and cidr > 0:
        cidr -= 1
        maskn >>= 1
    return cidr



def _cidr_to_mask(cidr):
    return socket.inet_ntop(
        socket.AF_INET, struct.pack(
            '!I', (2**32 - 1) ^ (2**(32 - cidr) - 1)))


def naturalize_string(key):
    """Analyzes string in a human way to enable natural sort

    :param nodename: The node name to analyze
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
        self.states = []
        if sensor:
            self.name = sensor['name']
        else:
            self.name = healthinfo['Name']
            self.health = _healthmap.get(healthinfo.get(
                'Status', {}).get('Health', None), const.Health.Warning)
            self.states = [healthinfo.get('Status', {}).get('Health',
                                                            'Unknown')]
            if self.health == const.Health.Ok:
                self.states = []
        self.value = value
        self.state_ids = None
        self.imprecision = None
        self.units = units
        self.unavailable = unavailable
    
    def __repr__(self):
        return repr({
            'value': self.value,
            'state_ids': self.state_ids,
            'units': self.units,
            'imprecision': self.imprecision,
            'name': self.name,
            'unavailable': self.unavailable,
        })


class Command(object):

    @classmethod
    async def create(cls, bmc, userid, password, verifycallback, sysurl=None,
                 bmcurl=None, chassisurl=None, pool=None, port=443):
        self = cls()
        self.wc = webclient.WebConnection(
            bmc, port, verifycallback=verifycallback)
        self._hwnamemap = {}
        self._fwnamemap = {}
        self._urlcache = {}
        self._varbmcurl = bmcurl
        self._varbiosurl = None
        self._varbmcnicurl = None
        self._varsetbiosurl = None
        self._varchassisurl = chassisurl
        self._varresetbmcurl = None
        self._varupdateservice = None
        self._varfwinventory = None
        self._oem = None
        self._gpool = pool
        self._bmcv4ip = None
        self._bmcv6ip = None
        self.xauthtoken = None
        for addrinf in socket.getaddrinfo(bmc, 0, 0, socket.SOCK_STREAM):
            if addrinf[0] == socket.AF_INET:
                self._bmcv4ip = socket.inet_pton(addrinf[0], addrinf[-1][0])
            elif addrinf[0] == socket.AF_INET6:
                theip = addrinf[-1][0]
                theip = theip.split('%')[0]
                self._bmcv6ip = socket.inet_pton(addrinf[0], theip)
        self.wc.set_header('Accept', 'application/json')
        self.wc.set_header('User-Agent', 'aiohmi')
        self.wc.set_header('Accept-Encoding', 'gzip')
        self.wc.set_header('OData-Version', '4.0')
        overview = await self.wc.grab_json_response('/redfish/v1/')
        self.username = userid
        self.password = password
        self.wc.set_basic_credentials(self.username, self.password)
        self.wc.set_header('Content-Type', 'application/json')
        if 'Systems' not in overview and 'Managers' not in overview:
            raise exc.PyghmiException('Redfish not ready')
        if 'SessionService' in overview:
            await self._get_session_token(self.wc)
        self._varsensormap = {}
        self.powerurl = None
        self.sysurl = None
        self._initsysurl = sysurl
        tmpoem = await oem.get_oem_handler({}, sysurl, self.wc, self._urlcache, self,
                                    rootinfo=overview)
        self._varbmcurl = await tmpoem.get_default_mgrurl()        
        if 'Systems' in overview:
            self.sysurl = await tmpoem.get_default_sysurl()
            sysinfo = await self.sysinfo()
            self.powerurl = sysinfo.get('Actions', {}).get(
                '#ComputerSystem.Reset', {}).get('target', None)               
        return self

    async def _get_session_token(self, wc):
        # specification actually indicates we can skip straight to this url
        username = self.username
        password = self.password
        if not isinstance(username, str):
            username = username.decode()
        if not isinstance(password, str):
            password = password.decode()
        _, status, headers = await wc.grab_response_with_status('/redfish/v1/SessionService/Sessions',
                          {'UserName': username, 'Password': password})
        if status > 299 or status < 200:
            return
        self.xauthtoken = headers.get('X-Auth-Token')
        if self.xauthtoken:
            if 'Authorization' in wc.stdheaders:
                del wc.stdheaders['Authorization']
            if 'Authorization' in self.wc.stdheaders:
                del self.wc.stdheaders['Authorization']
            wc.stdheaders['X-Auth-Token'] = self.xauthtoken
            self.wc.stdheaders['X-Auth-Token'] = self.xauthtoken

    async def _accountserviceurl(self):
        sroot = await self._do_web_request('/redfish/v1/')
        return sroot.get('AccountService', {}).get('@odata.id', None)

    async def _validroles(self):
        okroles = set()
        roleurl = (await self._do_web_request(await self._accountserviceurl())).get(
            'Roles', {}).get('@odata.id', None)
        if roleurl:
            roles = (await self._do_web_request(roleurl)).get('Members', [])
            for role in roles:
                role = role.get('@odata.id', '')
                if not role:
                    continue
                okroles.add(role.split('/')[-1])
        if not okroles:
            okroles.add('Administrator')
            okroles.add('Operator')
            okroles.add('ReadOnly')
        return okroles

    async def get_trusted_cas(self):
        oem = await self.oem()
        async for ca in oem.get_trusted_cas():
            yield ca
    
    async def get_bmc_csr(self, keytype=None, keylength=None, cn=None, city=None,
                    state=None, country=None, org=None, orgunit=None):
        oem = await self.oem()
        return await oem.get_bmc_csr(
            keytype=keytype, keylength=keylength, cn=cn)

    async def install_bmc_certificate(self, certdata):
        oem = await self.oem()
        return await oem.install_bmc_certificate(certdata)
    
    async def add_trusted_ca(self, pemdata):
        oem = await self.oem()
        return await oem.add_trusted_ca(pemdata)
    
    async def del_trusted_ca(self, certid):
        oem = await self.oem()
        return await oem.del_trusted_ca(certid)

    async def get_users(self):
        """get list of users and channel access information (helper)

        :param channel: number [1:7]

        :return:
            name: (str)
            uid: (int)
            channel: (int)
            access:
                callback (bool)
                link_auth (bool)
                ipmi_msg (bool)
                privilege_level: (str)[callback, user, operatorm administrator,
                                       proprietary, no_access]
        """
        srvurl = await self._accountserviceurl()
        names = {}
        if srvurl:
            srvinfo = await self._do_web_request(srvurl)
            srvurl = srvinfo.get('Accounts', {}).get('@odata.id', None)
            if srvurl:
                srvinfo = await self._do_web_request(srvurl)
                accounts = srvinfo.get('Members', [])
                oem = await self.oem()
                for account in accounts:
                    accinfo = await self._do_web_request(account['@odata.id'])
                    currname = accinfo.get('UserName', '')
                    currid = accinfo.get('Id', None)
                    if currname:
                        names[currid] = {
                            'name': currname,
                            'uid': currid,
                            'expiration': await oem.get_user_expiration(currid),
                            'access': {
                                'privilege_level': accinfo.get('RoleId',
                                                               'Unknown')
                            }
                        }
        return names

    async def _account_url_info_by_id(self, uid):
        srvurl = await self._accountserviceurl()
        oem = await self.oem()
        if srvurl:
            srvinfo = await self._do_web_request(srvurl)
            srvurl = srvinfo.get('Accounts', {}).get('@odata.id', None)
            if srvurl:
                srvinfo = await self._do_web_request(srvurl)
                accounts = srvinfo.get('Members', [])
                for account in accounts:
                    accinfo = await self._do_web_request(account['@odata.id'])
                    currid = accinfo.get('Id', None)
                    if str(currid) == str(uid):
                        accinfo['expiration'] = await oem.get_user_expiration(
                            uid)
                        return account['@odata.id'], accinfo

    async def get_user(self, uid):
        srvurl = await self._accountserviceurl()
        oem = await self.oem()
        if srvurl:
            srvinfo = await self._do_web_request(srvurl)
            srvurl = srvinfo.get('Accounts', {}).get('@odata.id', None)
            if srvurl:
                srvinfo = await self._do_web_request(srvurl)
                accounts = srvinfo.get('Members', [])
                for account in accounts:
                    accinfo = await self._do_web_request(account['@odata.id'])
                    currname = accinfo.get('UserName', '')
                    currid = accinfo.get('Id', None)
                    if str(currid) == str(uid):
                        oem = await self.oem()
                        return {'name': currname, 'uid': uid,
                                'expiration': await oem.get_user_expiration(
                                    uid),
                                'access': {
                                    'privilege_level': accinfo.get(
                                        'RoleId', 'Unknown')}}

    async def set_user_password(self, uid, mode='set_password', password=None):
        """Set user password and (modes)

        :param uid: id number of user.  see: get_names_uid()['name']

        :param mode:
            disable       = disable user connections
            enable        = enable user connections
            set_password  = set or ensure password

        :param password: Password
            (optional when mode is [disable or enable])

        :return:
            True on success
        """

        accinfo = await self._account_url_info_by_id(uid)
        if not accinfo:
            raise Exception("No such account found")
        etag = accinfo[1].get('@odata.etag', None)
        if mode == 'set_password':
            await self._do_web_request(accinfo[0], {'Password': password},
                                 method='PATCH', etag=etag)
        elif mode == 'disable':
            await self._do_web_request(accinfo[0], {'Enabled': False},
                                 method='PATCH', etag=etag)
        elif mode == 'enable':
            await self._do_web_request(accinfo[0], {'Enabled': True},
                                 method='PATCH', etag=etag)
        return True

    async def disable_user(self, uid, mode):
        """Disable User

        Just disable the User.
        This will not disable the password or revoke privileges.

        :param uid: user id
        :param mode:
            disable       = disable user connections
            enable        = enable user connections
        """
        await self.set_user_password(uid, mode)
        return True

    async def set_user_access(self, uid, privilege_level='ReadOnly'):
        if privilege_level.startswith('custom.'):
            privilege_level = privilege_level.replace('custom.', '')
        accinfo = await self._account_url_info_by_id(uid)
        if accinfo:
            method = 'PATCH'
        else:
            accinfo = ((await self._accountserviceurl()) + '/Accounts', {})
            method = 'POST'
        etag = accinfo[1].get('@odata.etag', None)
        for role in await self._validroles():
            if role.lower() == privilege_level.lower():
                privilege_level = role
                break
        await self._do_web_request(accinfo[0], {'RoleId': privilege_level},
                             method=method, etag=etag)

    async def create_user(self, uid, name, password, privilege_level='ReadOnly'):
        """create/ensure a user is created with provided settings

        :param privilege_level:
            User Privilege level.  Redfish role, commonly Administrator,
            Operator, and ReadOnly
        """
        accinfo = await self._account_url_info_by_id(uid)
        if not accinfo:
            raise Exception("Unable to find indicated uid")
        if privilege_level.startswith('custom.'):
            privilege_level = privilege_level.replace('custom.', '')
        for role in await self._validroles():
            if role.lower() == privilege_level.lower():
                privilege_level = role
                break
        etag = accinfo[1].get('@odata.etag', None)
        userinfo = {
            "UserName": name,
            "Password": password,
            "RoleId": privilege_level,
        }
        await self._do_web_request(accinfo[0], userinfo, method='PATCH', etag=etag)
        return True

    async def get_screenshot(self, outfile):
        oem = await self.oem()
        return await oem.get_screenshot(outfile)

    async def get_ikvm_methods(self):
        oem = await self.oem()
        return await oem.get_ikvm_methods()

    async def get_ikvm_launchdata(self):
        oem = await self.oem()
        return await oem.get_ikvm_launchdata()   

    async def user_delete(self, uid):
        oem = await self.oem()
        return await oem.user_delete(uid, self)

    async def set_user_name(self, uid, name):
        """Set user name

        :param uid: user id
        :param name: username
        """
        accinfo = await self._account_url_info_by_id(uid)
        if not accinfo:
            raise Exception("No such account found")
        etag = accinfo[1].get('@odata.etag', None)
        await self._do_web_request(accinfo[0], {'UserName': name}, method='PATCH',
                             etag=etag)
        return True

    async def _updateservice(self):
        if not self._varupdateservice:
            overview = await self._do_web_request('/redfish/v1/')
            us = overview.get('UpdateService', {}).get('@odata.id', None)
            if not us:
                raise exc.UnsupportedFunctionality(
                    'BMC does not implement extended firmware information')
            self._varupdateservice = us
        return self._varupdateservice

    async def get_fwinventory(self):
        if not self._varfwinventory:
            usi = await self._do_web_request(await self._updateservice())
            self._varfwinventory = usi.get('FirmwareInventory', {}).get(
                '@odata.id', None)
            if not self._varfwinventory:
                raise exc.UnsupportedFunctionality(
                    'BMC does not implement extended firmware information')
        return self._varfwinventory

    async def sysinfo(self):
        if not self.sysurl:
            return {}
        try:
            return await self._do_web_request(self.sysurl)
        except exc.RedfishError:
            self.sysurl = None
            return {}

    async def bmcinfo(self):
        bmcurl = await self.get_bmcurl()
        return await self._do_web_request(bmcurl)

    async def get_power(self):
        currinfo = await self._do_web_request(self.sysurl, cache=False)
        return {'powerstate': str(currinfo['PowerState'].lower())}

    async def reseat_bay(self, bay):
        """Request the reseat of a bay

        Request the enclosure manager to reseat the system in a particular
        bay.

        :param bay: The bay identifier to reseat
        :return:
        """
        oem = await self.oem()
        await oem.reseat_bay(bay)

    async def set_power(self, powerstate, wait=False):
        if powerstate == 'boot':
            oldpowerstate = (await self.get_power())['powerstate']
            powerstate = 'on' if oldpowerstate == 'off' else 'reset'
        elif powerstate in ('on', 'off'):
            oldpowerstate = (await self.get_power())['powerstate']
            if oldpowerstate == powerstate:
                return {'powerstate': powerstate}
        reqpowerstate = powerstate
        if powerstate not in powerstates:
            raise exc.InvalidParameterValue(
                "Unknown power state %s requested" % powerstate)
        powerstate = powerstates[powerstate]
        await self._do_web_request(
            self.powerurl, {'ResetType': powerstate})
        if wait and reqpowerstate in ('on', 'off', 'softoff', 'shutdown'):
            if reqpowerstate in ('softoff', 'shutdown'):
                reqpowerstate = 'off'
            timeout = os.times()[4] + 300
            while (await self.get_power())['powerstate'] != reqpowerstate and os.times()[4] < timeout:
                await asyncio.sleep(1)
            if (await self.get_power())['powerstate'] != reqpowerstate:
                raise exc.PyghmiException(
                    "System did not accomplish power state change")
            return {'powerstate': reqpowerstate}
        return {'pendingpowerstate': reqpowerstate}

    def _get_cache(self, url, cache=30):
        now = os.times()[4]
        cachent = self._urlcache.get(url, None)
        if cachent and cachent['vintage'] > now - cache:
            return cachent['contents']
        return None

    async def _do_bulk_requests(self, urls, cache=True):
        if self._gpool:
            urls = [(x, None, None, cache) for x in urls]
            for res in self._gpool.starmap(self._do_web_request_withurl, urls):
                yield res
        else:
            for url in urls:
                yield await self._do_web_request_withurl(url, cache=cache)

    async def _do_web_request_withurl(self, url, payload=None, method=None,
                                cache=True):
        return await self._do_web_request(url, payload, method, cache), url

    async def _do_web_request(self, url, payload=None, method=None, cache=True,
                        etag=None):
        res = None
        if cache is True:
            cache = 30
        if cache and payload is None and method is None:
            res = self._get_cache(url, cache)
        if res:
            return res
        wc = self.wc
        if etag:
            wc.stdheaders['If-Match'] = etag
        try:
            res = await wc.grab_json_response_with_status(url, payload,
                                                    method=method)
        finally:
            if 'If-Match' in wc.stdheaders:
                del wc.stdheaders['If-Match']
        if res[1] == 401 and self.xauthtoken:
            wc.set_basic_credentials(self.username, self.password)
            await self._get_session_token(wc)
            if etag:
                wc.stdheaders['If-Match'] = etag
            try:
                res = await wc.grab_json_response_with_status(url, payload,
                                                              method=method)
            finally:
                if 'If-Match' in wc.stdheaders:
                    del wc.stdheaders['If-Match']

        if res[1] < 200 or res[1] >= 300:
            try:
                info = json.loads(res[0])
                errmsg = [
                    x.get('Message', x['MessageId']) for x in info.get(
                        'error', {}).get('@Message.ExtendedInfo', {})]
                msgid = [
                    x['MessageId'] for x in info.get(
                        'error', {}).get('@Message.ExtendedInfo', {})]
                errmsg = ','.join(errmsg)
                msgid = ','.join(msgid)
                raise exc.RedfishError(errmsg, msgid=msgid)
            except (ValueError, KeyError):
                raise exc.PyghmiException(str(url) + ":" + str(res[0]))
        if payload is None and method is None:
            self._urlcache[url] = {'contents': res[0],
                                   'vintage': os.times()[4]}
        return res[0]

    async def get_bootdev(self):
        """Get current boot device override information.

        :raises: PyghmiException on error
        :returns: dict
        """
        result = await self._do_web_request(self.sysurl)
        overridestate = result.get('Boot', {}).get(
            'BootSourceOverrideEnabled', None)
        if overridestate == 'Disabled':
            return {'bootdev': 'default', 'persistent': True}
        persistent = None
        if overridestate == 'Once':
            persistent = False
        elif overridestate == 'Continuous':
            persistent = True
        else:
            raise exc.PyghmiException('Unrecognized Boot state: %s'
                                      % repr(overridestate))
        uefimode = result.get('Boot', {}).get('BootSourceOverrideMode', None)
        if uefimode == 'UEFI':
            uefimode = True
        elif uefimode == 'Legacy':
            uefimode = False
        else:
            raise exc.PyghmiException('Unrecognized mode: %s' % uefimode)
        bootdev = result.get('Boot', {}).get('BootSourceOverrideTarget', None)
        if bootdev not in boot_devices_read:
            raise exc.PyghmiException('Unrecognized boot target: %s'
                                      % repr(bootdev))
        bootdev = boot_devices_read[bootdev]
        return {'bootdev': bootdev, 'persistent': persistent,
                'uefimode': uefimode}

    async def set_bootdev(self, bootdev, persist=False, uefiboot=None):
        """Set boot device to use on next reboot

        :param bootdev:
                        *network -- Request network boot
                        *hd -- Boot from hard drive
                        *safe -- Boot from hard drive, requesting 'safe mode'
                        *optical -- boot from CD/DVD/BD drive
                        *setup -- Boot into setup utility
                        *default -- remove any directed boot device request
        :param persist: If true, ask that system firmware use this device
                        beyond next boot.  Be aware many systems do not honor
                        this
        :param uefiboot: If true, request UEFI boot explicitly.  If False,
                         request BIOS style boot.
                         None (default) does not modify the boot mode.
        :raises: PyghmiException on an error.
        :returns: dict or True -- If callback is not provided, the response
        """
        oem = await self.oem()
        return await oem.set_bootdev(bootdev, persist, uefiboot, self)

    async def get_biosurl(self):
        if not self._varbiosurl:
            sysinfo = await self.sysinfo()
            self._varbiosurl = sysinfo.get('Bios', {}).get('@odata.id',
                                                          None)
        if self._varbiosurl is None:
            raise exc.UnsupportedFunctionality(
                'Bios management not detected on this platform')
        return self._varbiosurl

    async def get_setbiosurl(self):
        if self._varsetbiosurl is None:
            biosinfo = await self._do_web_request(await self.get_biosurl())
            self._varsetbiosurl = biosinfo.get(
                '@Redfish.Settings', {}).get('SettingsObject', {}).get(
                    '@odata.id', None)
        if self._varsetbiosurl is None:
            raise exc.UnsupportedFunctionality('Ability to set BIOS settings '
                                               'not detected on this platform')
        return self._varsetbiosurl

    async def _sensormap(self):
        if not self._varsensormap:
            sysinfo = await self.sysinfo()
            if sysinfo:
                for chassis in sysinfo.get('Links', {}).get('Chassis', []):
                    await self._mapchassissensors(chassis)
            else:  # no system, but check if this is a singular chassis
                rootinfo = await self._do_web_request('/redfish/v1/')
                chassiscol = rootinfo.get('Chassis', {}).get('@odata.id', '')
                if chassiscol:
                    chassislist = await self._do_web_request(chassiscol)
                    if len(chassislist.get('Members', [])) == 1:
                        await self._mapchassissensors(chassislist['Members'][0])
        return self._varsensormap

    async def _mapchassissensors(self, chassis):
        chassisurl = chassis['@odata.id']
        chassisinfo = await self._do_web_request(chassisurl)
        sensors = None
        oem = await self.oem()
        if oem.usegenericsensors:
            sensors = chassisinfo.get('Sensors', {}).get('@odata.id', '')
        if sensors:
            sensorinf = await self._do_web_request(sensors)
            for sensor in sensorinf.get('Members', []):
                sensedata = await self._do_web_request(sensor['@odata.id'])
                if 'Name' in sensedata:
                    sensetype = sensedata.get('ReadingType', 'Unknown')
                    self._varsensormap[sensedata['Name']] = {
                        'name': sensedata['Name'], 'type': sensetype,
                        'url': sensor['@odata.id'], 'generic': True}
        else:
            powurl = chassisinfo.get('Power', {}).get('@odata.id', '')
            if powurl:
                powinf = await self._do_web_request(powurl)
                for voltage in powinf.get('Voltages', []):
                    if 'Name' in voltage:
                        self._varsensormap[voltage['Name']] = {
                            'name': voltage['Name'], 'url': powurl,
                            'type': 'Voltage'}
            thermurl = chassisinfo.get('Thermal', {}).get('@odata.id', '')
            if thermurl:
                therminf = await self._do_web_request(thermurl)
                for fan in therminf.get('Fans', []):
                    if 'Name' in fan:
                        self._varsensormap[fan['Name']] = {
                            'name': fan['Name'], 'type': 'Fan',
                            'url': thermurl}
                for temp in therminf.get('Temperatures', []):
                    if 'Name' in temp:
                        self._varsensormap[temp['Name']] = {
                            'name': temp['Name'], 'type': 'Temperature',
                            'url': thermurl}      
        for subchassis in chassisinfo.get('Links', {}).get('Contains', []):
            await self._mapchassissensors(subchassis)

    async def _get_thermals(self, chassis):
        chassisurl = chassis['@odata.id']
        chassisinfo = await self._do_web_request(chassisurl)
        thermurl = chassisinfo.get('Thermal', {}).get('@odata.id', '')
        if thermurl:
            therminf = await self._do_web_request(thermurl, cache=1)
            return therminf.get('Temperatures', [])

    async def get_bmcurl(self):
        if not self._varbmcurl:
            sysinfo = await self.sysinfo()
            self._varbmcurl = sysinfo.get('Links', {}).get(
                'ManagedBy', [{}])[0].get('@odata.id', None)
        return self._varbmcurl

    async def get_bmcnicurl(self):
        if not self._varbmcnicurl:
            self._varbmcnicurl = await self._get_bmc_nic_url()
        return self._varbmcnicurl

    async def list_network_interface_names(self):
        bmcurl = await self.get_bmcurl()
        bmcinfo = await self._do_web_request(bmcurl)
        nicurl = bmcinfo.get('EthernetInterfaces', {}).get('@odata.id', None)
        if not nicurl:
            return
        niclist = await self._do_web_request(nicurl)
        for nic in niclist.get('Members', []):
            curl = nic.get('@odata.id', None)
            if not curl:
                continue
            yield curl.rsplit('/', 1)[1]

    async def _get_bmc_nic_url(self, name=None):
        bmcinfo = await self._do_web_request(await self.get_bmcurl())
        nicurl = bmcinfo.get('EthernetInterfaces', {}).get('@odata.id', None)
        niclist = await self._do_web_request(nicurl)
        foundnics = 0
        lastnicurl = None
        oem = await self.oem()
        for nic in niclist.get('Members', []):
            curl = nic.get('@odata.id', None)
            if not curl:
                continue
            if name is not None:
                if curl.endswith('/{0}'.format(name)):
                    return curl
                continue
            if oem.hostnic and curl.endswith('/{0}'.format(
                    oem.hostnic)):
                continue
            nicinfo = await self._do_web_request(curl)
            if nicinfo.get('Links', {}).get('HostInterface', None):
                # skip host interface
                continue
            if not nicinfo.get('InterfaceEnabled', True):
                # skip disabled interfaces
                continue
            for addrs in nicinfo.get('IPv4Addresses', []):
                v4addr = socket.inet_pton(
                    socket.AF_INET, addrs.get('Address', '0.0.0.0'))
                if self._bmcv4ip == v4addr:
                    return curl
            for addrs in nicinfo.get('IPv6Addresses', []):
                v6addr = socket.inet_pton(
                    socket.AF_INET6, addrs.get('Address', '::'))
                if self._bmcv6ip == v6addr:
                    return curl
            foundnics += 1
            lastnicurl = curl
        if name is None and foundnics != 1:
            raise exc.PyghmiException(
                'BMC does not have exactly one interface')
        if name is None:
            return lastnicurl

    async def _bmcresetinfo(self):
        if not self._varresetbmcurl:
            bmcinfo = await self._do_web_request(await self.get_bmcurl())
            resetinf = bmcinfo.get('Actions', {}).get('#Manager.Reset', {})
            url = resetinf.get('target', '')
            valid = resetinf.get('ResetType@Redfish.AllowableValues', [])
            if not valid:
                tmpurl = resetinf.get('@Redfish.ActionInfo', None)
                if tmpurl:
                    resetinf = await self._do_web_request(tmpurl)
                    valid = resetinf.get('Parameters', [{}])[0].get(
                        'AllowableValues')
            resettype = None
            if 'GracefulRestart' in valid:
                resettype = 'GracefulRestart'
            elif 'ForceRestart' in valid:
                resettype = 'ForceRestart'
            elif 'ColdReset' in valid:
                resettype = 'ColdReset'
            self._varresetbmcurl = url, resettype
        return self._varresetbmcurl

    async def reset_bmc(self):
        url, action = await self._bmcresetinfo()
        if not url:
            raise Exception('BMC does not provide reset action')
        if not action:
            raise Exception('BMC does not accept a recognized reset type')
        await self._do_web_request(url, {'ResetType': action})

    async def set_identify(self, on=True, blink=None):
        oem = await self.oem()
        if hasattr(oem, 'set_identify'):
            return await oem.set_identify(on, blink)    
        targurl = self.sysurl
        if not targurl:
            root = await self._do_web_request('/redfish/v1')
            systemsurl = root.get('Systems', {}).get('@odata.id', None)
            if systemsurl:
                targurl = await self._do_web_request(systemsurl)
                if len(targurl.get('Members', [])) == 1:
                    targurl = targurl['Members'][0]['@odata.id']
        if not targurl:
            raise Exception("Unable to identify system url")        
        await self._do_web_request(
            targurl,
            {'IndicatorLED': 'Blinking' if blink else 'Lit' if on else 'Off'},
            method='PATCH', etag='*')

    _idstatemap = {
        'Blinking': 'blink',
        'Lit': 'on',
        'Off': 'off',
    }

    async def get_identify(self):
        await self.sysinfo()
        ledstate = self.sysinfo
        return {'identifystate': self._idstatemap[ledstate]}

    async def get_health(self, verbose=True):
        oem = await self.oem()
        return await oem.get_health(self, verbose)

    async def get_extended_bmc_configuration(self, hideadvanced=True):
        oem = await self.oem()
        return await oem.get_extended_bmc_configuration(self, hideadvanced=hideadvanced)

    async def get_bmc_configuration(self):
        """Get miscellaneous BMC configuration

        In much the same way a bmc can present arbitrary key-value
        structure for BIOS/UEFI configuration, provide a mechanism
        for a BMC to provide arbitrary key-value for BMC specific
        settings.
        """

        # For now, this is a stub, no implementation for redfish currently
        oem = await self.oem()
        return await oem.get_bmc_configuration()

    async def set_bmc_configuration(self, changeset):
        """Get miscellaneous BMC configuration

        In much the same way a bmc can present arbitrary key-value
        structure for BIOS/UEFI configuration, provide a mechanism
        for a BMC to provide arbitrary key-value for BMC specific
        settings.
        """

        # For now, this is a stub, no implementation for redfish currently
        oem = await self.oem()
        return await oem.set_bmc_configuration(changeset)

    async def set_system_configuration(self, changeset):
        oem = await self.oem()
        return await oem.set_system_configuration(changeset, self)

    async def get_ntp_enabled(self):
        bmcinfo = await self._do_web_request(await self.get_bmcurl())
        netprotocols = bmcinfo.get('NetworkProtocol', {}).get('@odata.id', None)
        if netprotocols:
            netprotoinfo = await self._do_web_request(netprotocols)
            enabled = netprotoinfo.get('NTP', {}).get('ProtocolEnabled', False)
            return enabled
        return False

    async def set_ntp_enabled(self, enable):
        bmcinfo = await self._do_web_request(await self.get_bmcurl())
        netprotocols = bmcinfo.get('NetworkProtocol', {}).get('@odata.id', None)
        if netprotocols:
            request = {'NTP':{'ProtocolEnabled': enable}}
            await self._do_web_request(netprotocols, request, method='PATCH')
            await self._do_web_request(netprotocols, cache=0)

    async def get_ntp_servers(self):
        bmcinfo = await self._do_web_request(await self.get_bmcurl())
        netprotocols = bmcinfo.get('NetworkProtocol', {}).get('@odata.id', None)
        if not netprotocols:
            return []
        netprotoinfo = await self._do_web_request(netprotocols)
        return netprotoinfo.get('NTP', {}).get('NTPServers', [])

    async def set_ntp_server(self, server, index=None):
        bmcinfo = await self._do_web_request(await self.get_bmcurl())
        netprotocols = bmcinfo.get('NetworkProtocol', {}).get('@odata.id', None)
        currntpservers = await self.get_ntp_servers()
        if index is None:
            if server in currntpservers:
                return
            currntpservers = [server] + currntpservers
        else:
            if (index + 1) > len(currntpservers):
                if not server:
                    return
                currntpservers.append(server)
            else:
                if not server:
                    del currntpservers[index]
                else:
                    currntpservers[index] = server
        request = {'NTP':{'NTPServers': currntpservers}}
        await self._do_web_request(netprotocols, request, method='PATCH')
        await self._do_web_request(netprotocols, cache=0)

    async def clear_bmc_configuration(self):
        """Reset BMC to factory default

        Call appropriate function to clear BMC to factory default settings.
        In many cases, this may render remote network access impracticle or
        impossible."
        """
        bmcinfo = await self._do_web_request(await self.get_bmcurl())
        rc = bmcinfo.get('Actions', {}).get('#Manager.ResetToDefaults', {})
        actinf = rc.get('ResetType@Redfish.AllowableValues', [])
        if 'ResetAll' in actinf: 
            acturl = rc.get('target', None)
            if acturl:
                await self._do_web_request(acturl, {'ResetType': 'ResetAll'})
                return
        raise exc.UnsupportedFunctionality(
            'Clear BMC configuration not supported on this platform')

    async def get_system_configuration(self, hideadvanced=True):
        oem = await self.oem()
        return await oem.get_system_configuration(hideadvanced, self)

    async def clear_system_configuration(self):
        """Clear the BIOS/UEFI configuration

        """
        biosinfo = await self._do_web_request(await self.get_biosurl())
        rb = biosinfo.get('Actions', {}).get('#Bios.ResetBios', {})
        actinf = rb.get('@Redfish.ActionInfo', None)
        rb = rb.get('target', '')
        parms = {}
        if actinf:
            actinf = await self._do_web_request(
                '/redfish/v1/Systems/Self/Bios/ResetBiosActionInfo')
            for parm in actinf.get('Parameters', ()):
                if parm.get('Required', False):
                    if parm.get('Name', None) == 'ResetType' and parm.get(
                            'AllowableValues', [None])[0] == 'Reset':
                        parms['ResetType'] = 'Reset'
                    else:
                        raise Exception(
                            'Unrecognized required parameter {0}'.format(
                                parm.get('Name', 'Unknown')))
        if not rb:
            raise Exception('BIOS reset not detected on this system')
        if not parms:
            parms = {'Action': 'Bios.ResetBios'}
        await self._do_web_request(rb, parms)

    async def set_net6_configuration(self, static_addresses=None, static_gateway=None, name=None):
        patch = {}
        if static_addresses is not None:
            sa = []
            patch['IPv6StaticAddresses'] = sa
            for addr in static_addresses:
                if '/' in addr:
                    addr, plen = addr.split('/', 1)
                else:
                    plen = '64'
                sa.append({
                    'PrefixLength': int(plen),
                    'Address': addr
                })
        if static_gateway:
            patch['IPv6StaticDefaultGateways'] = [{
                'Address': static_gateway,
            }]
        if patch:
            nicurl = self._get_bmc_nic_url(name)
            await self._do_web_request(nicurl, patch, 'PATCH')

    async def set_net_configuration(self, ipv4_address=None, ipv4_configuration=None,
                              ipv4_gateway=None, vlan_id=None, name=None):
        patch = {}
        ipinfo = {}
        dodhcp = None
        netmask = None
        if (ipv4_address is None and ipv4_configuration is None
                and ipv4_gateway is None and vlan_id is None):
            return
        if ipv4_address:
            if '/' in ipv4_address:
                ipv4_address, cidr = ipv4_address.split('/')
                netmask = _cidr_to_mask(int(cidr))
            patch['IPv4StaticAddresses'] = [ipinfo]
            ipinfo['Address'] = ipv4_address
            ipv4_configuration = 'static'
            if netmask:
                ipinfo['SubnetMask'] = netmask
        if ipv4_gateway:
            patch['IPv4StaticAddresses'] = [ipinfo]
            ipinfo['Gateway'] = ipv4_gateway
            ipv4_configuration = 'static'
        if ipv4_configuration and ipv4_configuration.lower() == 'dhcp':
            dodhcp = True
            patch['DHCPv4'] = {'DHCPEnabled': True}
        elif (ipv4_configuration == 'static'
              or 'IPv4StaticAddresses' in patch):
            dodhcp = False
            patch['DHCPv4'] = {'DHCPEnabled': False}
        if vlan_id in ('off', 0, '0'):
            patch['VLAN'] = {'VLANEnable': False}
        elif vlan_id:
            patch['VLAN'] = {'VLANEnable': True, 'VLANId': int(vlan_id)}        
        if patch:
            nicurl = await self._get_bmc_nic_url(name)
            try:
                await self._do_web_request(nicurl, patch, 'PATCH')
            except exc.RedfishError:
                patch = {'IPv4Addresses': [ipinfo]}
                if dodhcp:
                    ipinfo['AddressOrigin'] = 'DHCP'
                elif dodhcp is not None:
                    ipinfo['AddressOrigin'] = 'Static'
                await self._do_web_request(nicurl, patch, 'PATCH')

    async def get_net6_configuration(self, name=None):
        nicurl = await self._get_bmc_nic_url(name)
        netcfg = await self._do_web_request(nicurl, cache=False)
        retdata = {}
        saddrs = netcfg.get('IPv6StaticAddresses', ())
        retdata['static_addrs'] = []
        for sa in saddrs:
            ca = '{}/{}'.format(sa['Address'], sa['PrefixLength'])
            retdata['static_addrs'].append(ca)
        gws = netcfg.get('IPv6StaticDefaultGateways', None)
        if gws:
            for gw in gws:
                retdata['static_gateway'] = gw['Address']
        tagged = netcfg.get('VLAN', {}).get('VLANEnabled', False)
        if tagged:
            retdata['vlan_id'] = netcfg.get('VLAN', {}).get('VLANId', None)
        else:
            retdata['vlan_id'] = 'off'
        return retdata

    async def get_net_configuration(self, name=None):
        nicurl = await self._get_bmc_nic_url(name)
        netcfg = await self._do_web_request(nicurl, cache=False)
        ipv4 = netcfg.get('IPv4Addresses', {})
        if not ipv4:
            raise exc.PyghmiException('Unable to locate network information')
        retval = {}
        if len(netcfg['IPv4Addresses']) != 1:
            netcfg['IPv4Addresses'] = [
                x for x in netcfg['IPv4Addresses']
                if x['Address'] != '0.0.0.0']
        if len(netcfg['IPv4Addresses']) != 1:
            raise exc.PyghmiException('Multiple IP addresses not supported')
        currip = netcfg['IPv4Addresses'][0]
        cidr = _mask_to_cidr(currip['SubnetMask'])
        retval['ipv4_address'] = '{0}/{1}'.format(currip['Address'], cidr)
        retval['mac_address'] = netcfg['MACAddress']
        hasgateway = _mask_to_cidr(currip['Gateway']) if currip.get('Gateway', None) else None
        retval['ipv4_gateway'] = currip['Gateway'] if hasgateway else None
        retval['ipv4_configuration'] = currip['AddressOrigin']
        tagged = netcfg.get('VLAN', {}).get('VLANEnable', False)
        if tagged:
            retval['vlan_id'] = netcfg.get('VLAN', {}).get('VLANId', None)
        else:
            retval['vlan_id'] = 'off'        
        return retval

    async def get_hostname(self):
        netcfg = await self._do_web_request(await self.get_bmcnicurl())
        return netcfg['HostName']

    async def set_hostname(self, hostname):
        await self._do_web_request(await self.get_bmcnicurl(),
                             {'HostName': hostname}, 'PATCH')

    async def get_firmware(self, components=(), category=None):
        self._fwnamemap = {}
        oem = await self.oem()
        try:
            async for firminfo in oem.get_firmware_inventory(components, self, category):
                yield firminfo
        except exc.BypassGenericBehavior:
            return
        fwlist = await self._do_web_request(await self.get_fwinventory())
        fwurls = [x['@odata.id'] for x in fwlist.get('Members', [])]
        async for res in self._do_bulk_requests(fwurls):
            res = self._extract_fwinfo(res)
            if res[0] is None:
                continue
            yield res

    def _extract_fwinfo(self, inf):
        currinf = self._oem._extract_fwinfo(inf)
        fwi, url = inf
        fwname = fwi.get('Name', 'Unknown')
        if fwname in self._fwnamemap:
            fwname = fwi.get('Id', fwname)
        if fwname in self._fwnamemap:
            # Block duplicates for by name retrieval
            self._fwnamemap[fwname] = None
        else:
            self._fwnamemap[fwname] = url
        currinf['name'] = fwname
        currinf['id'] = fwi.get('Id', None)
        currinf['version'] = fwi.get('Version', 'Unknown')
        currinf['date'] = parse_time(fwi.get('ReleaseDate', ''))
        currinf['software_id'] = fwi.get('SoftwareId', '')
        if not (currinf['version'] or currinf['date']):
            return None, None
        # TODO(Jarrod Johnson): OEM extended data with buildid
        currstate = fwi.get('Status', {}).get('State', 'Unknown')
        if currstate == 'StandbyOffline':
            currinf['state'] = 'pending'
        elif currstate == 'Enabled':
            currinf['state'] = 'active'
        elif currstate == 'StandbySpare':
            currinf['state'] = 'backup'
        return fwname, currinf

    async def get_inventory_descriptions(self, withids=False):
        oem = await self.oem()
        async for desc in oem.get_inventory_descriptions(withids):
            yield desc

    async def get_inventory_of_component(self, component):
        oem = await self.oem()
        return await oem.get_inventory_of_component(component)

    async def get_inventory(self, withids=False):
        oem = await self.oem()
        async for x in oem.get_inventory(withids):
            yield x

    async def get_location_information(self):
        locationinfo = {}
        sysinfo = await self.sysinfo()
        for chassis in sysinfo.get('Links', {}).get('Chassis', []):
            chassisurl = chassis['@odata.id']
            data = await self._do_web_request(chassisurl)
            locdata = data.get('Location', {})
            postaladdress = locdata.get('PostalAddress', {})
            placement = locdata.get('Placement', {})
            contactinfo = locdata.get('Contacts', [])
            currval = postaladdress.get('Room', '')
            if currval:
                locationinfo['room'] = currval
            currval = postaladdress.get('Location', '')
            if currval:
                locationinfo['location'] = currval
            currval = postaladdress.get('Building', '')
            if currval:
                locationinfo['building'] = currval
            currval = placement.get('Rack', '')
            if currval:
                locationinfo['rack'] = currval
            for contact in contactinfo:
                contact = contact.get('ContactName', '')
                if not contact:
                    continue
                if 'contactnames' not in locationinfo:
                    locationinfo['contactnames'] = [contact]
                else:
                    locationinfo['contactnames'].append(contact)
        return locationinfo

    async def set_location_information(self, room=None, contactnames=None,
                                 location=None, building=None, rack=None):
        locationinfo = {}
        postaladdress = {}
        placement = {}
        if contactnames is not None:
            locationinfo['Contacts'] = [
                {'ContactName': x} for x in contactnames]
        if room is not None:
            postaladdress['Room'] = room
        if location is not None:
            postaladdress['Location'] = location
        if building is not None:
            postaladdress['Building'] = building
        if rack is not None:
            placement['Rack'] = rack
        if postaladdress:
            locationinfo['PostalAddress'] = postaladdress
        if placement:
            locationinfo['Placement'] = placement
        if locationinfo:
            sysinfo = await self.sysinfo()
            for chassis in sysinfo.get('Links', {}).get('Chassis', []):
                chassisurl = chassis['@odata.id']
                await self._do_web_request(chassisurl, {'Location': locationinfo},
                                     method='PATCH')

    async def oem(self):
        if not self._oem:
            if self.sysurl:
                await self._do_web_request(self.sysurl, cache=False)  # This is to trigger token validation and renewel
            elif self._varbmcurl:
                await self._do_web_request(self._varbmcurl, cache=False)  # This is to trigger token validation and renewel
            sysinfo = await self.sysinfo()
            self._oem = await oem.get_oem_handler(
                sysinfo, self._initsysurl, self.wc, self._urlcache, self)
            self._oem.set_credentials(self.username, self.password)
        return self._oem

    async def get_description(self):
        oem = await self.oem()
        return await oem.get_description(self)

    async def get_event_log(self, clear=False):
        oem = await self.oem()
        async for logent in oem.get_event_log(clear, self):
            yield logent
    
    async def _get_chassis_env(self, chassis):
        chassisurl = chassis['@odata.id']
        chassisinfo = await self._do_web_request(chassisurl)
        envurl = chassisinfo.get('EnvironmentMetrics', {}).get('@odata.id', '')
        if not envurl:
            return {}
        envmetric = await self._do_web_request(envurl, cache=1)
        retval = {
            'watts': envmetric.get('PowerWatts', {}).get('Reading', None),
            'inlet': envmetric.get('TemperatureCelsius', {}).get('Reading', None)
        }
        return retval

    async def get_average_processor_temperature(self):
        oem = await self.oem()
        return await oem.get_average_processor_temperature(self)

    async def get_system_power_watts(self):
        oem = await self.oem()
        return await oem.get_system_power_watts(self)

    async def get_inlet_temperature(self):
        inlets = []
        sysinfo = await self.sysinfo()
        for chassis in sysinfo.get('Links', {}).get('Chassis', []):
            envinfo = await self._get_chassis_env(chassis)
            currinlet = envinfo.get('inlet', None)
            if currinlet:
                inlets.append(currinlet)
        if inlets:
            val = sum(inlets) / len(inlets)
            unavail = False
        else:
            val = None
            unavail = True
        return SensorReading(
                        None, {'name': 'Inlet Temperature'}, value=val, units='°C',
                        unavailable=unavail)
    async def get_sensor_descriptions(self):
        for sensor in natural_sort(await self._sensormap()):
            yield (await self._sensormap())[sensor]

    async def get_sensor_reading(self, sensorname):
        sensormap = await self._sensormap()
        if sensorname not in sensormap:
            raise Exception('Sensor not found')
        sensor = sensormap[sensorname]
        reading = await self._do_web_request(sensor['url'], cache=1)
        return self._extract_reading(sensor, reading)

    async def get_sensor_data(self):
        for sensor in natural_sort(await self._sensormap()):
            yield await self.get_sensor_reading(sensor)

    def _extract_reading(self, sensor, reading):
        if sensor.get('generic', False):  # generic sensor
            val = reading.get('Reading', None)
            unavail = val is None
            units = reading.get('ReadingUnits', None)
            if units == 'Cel':
                units = '°C'
            if units == 'cft_i/min':
                units = 'CFM'
            return SensorReading(reading, None, value=val, units=units,
                          unavailable=unavail)
        if sensor['type'] == 'Fan':
            for fan in reading['Fans']:
                if fan['Name'] == sensor['name']:
                    val = fan.get('Reading', None)
                    unavail = val is None
                    units = fan.get('ReadingUnits', None)
                    return SensorReading(
                        None, sensor, value=val, units=units,
                        unavailable=unavail)
        elif sensor['type'] == 'Temperature':
            for temp in reading['Temperatures']:
                if temp['Name'] == sensor['name']:
                    val = temp.get('ReadingCelsius', None)
                    unavail = val is None
                    return SensorReading(
                        None, sensor, value=val, units='°C',
                        unavailable=unavail)
        elif sensor['type'] == 'Voltage':
            for volt in reading['Voltages']:
                if volt['Name'] == sensor['name']:
                    val = volt.get('ReadingVolts', None)
                    unavail = val is None
                    return SensorReading(
                        None, sensor, value=val, units='V',
                        unavailable=unavail)

    async def list_media(self):
        oem = await self.oem()
        async for res in oem.list_media(self):
            yield res

    async def get_storage_configuration(self):
        """"Get storage configuration data

        Retrieves the storage configuration from the target.  Data is given
        about disks, pools, and volumes.  When referencing something, use the
        relevant 'cfgpath' attribute to describe it.  It is not guaranteed that
        cfgpath will be consistent version to version, so a lookup is suggested
        in end user applications.

        :return: A aiohmi.storage.ConfigSpec object describing current config
        """
        oem = await self.oem()
        return await oem.get_storage_configuration()

    async def remove_storage_configuration(self, cfgspec):
        """Remove specified storage configuration from controller.

        :param cfgspec: A aiohmi.storage.ConfigSpec describing what to remove
        :return:
        """
        oem = await self.oem()
        return await oem.remove_storage_configuration(cfgspec)

    async def apply_storage_configuration(self, cfgspec=None):
        """Evaluate a configuration for validity

        This will check if configuration is currently available and, if given,
        whether the specified cfgspec can be applied.
        :param cfgspec: A aiohmi.storage.ConfigSpec describing desired oonfig
        :return:
        """
        oem = await self.oem()
        return await oem.apply_storage_configuration(cfgspec)

    def check_storage_configuration(self, cfgspec=None):
        """Evaluate a configuration for validity

        This will check if configuration is currently available and, if given,
        whether the specified cfgspec can be applied.
        :param cfgspec: A aiohmi.storage.ConfigSpec describing desired oonfig
        :return:
        """
        return self._oem.check_storage_configuration(cfgspec)

    async def attach_remote_media(self, url, username=None, password=None):
        """Attach remote media by url

        Given a url, attach remote media (cd/usb image) to the target system.

        :param url:  URL to indicate where to find image (protocol support
                     varies by BMC)
        :param username: Username for endpoint to use when accessing the URL.
                         If applicable, 'domain' would be indicated by '@' or
                         '\' syntax.
        :param password: Password for endpoint to use when accessing the URL.
        """
        # At the moment, there isn't a viable way to
        # identify the correct resource ahead of time.
        # As such it's OEM specific until the standard
        # provides a better way.
        vmurls = []
        sysinfo = await self.sysinfo()
        vmcoll = sysinfo.get(
            'VirtualMedia', {}).get('@odata.id', None)
        if not vmcoll:
            bmcinfo = await self.bmcinfo()
            vmcoll = bmcinfo.get(
                'VirtualMedia', {}).get('@odata.id', None)
        if vmcoll:
            vmlist = await self._do_web_request(vmcoll)
            vmurls = [x['@odata.id'] for x in vmlist.get('Members', [])]
        suspendedxauth = False  # Don't trigger token expiry linked unmount
        if 'X-Auth-Token' in self.wc.stdheaders:
            suspendedxauth = True
            del self.wc.stdheaders['X-Auth-Token']
            self.wc.set_basic_credentials(self.username, self.password)
        oem = await self.oem()
        try:
            await oem.attach_remote_media(url, username, password, vmurls)
        except exc.BypassGenericBehavior:
            if suspendedxauth:
                self.wc.stdheaders['X-Auth-Token'] = self.xauthtoken
                if 'Authorization' in self.wc.stdheaders:
                    del self.wc.stdheaders['Authorization']            
            return
        for vmurl in vmurls:
            vminfo = self._do_web_request(vmurl, cache=False)
            if vminfo.get('ConnectedVia', None) != 'NotConnected':
                continue
            inserturl = vminfo.get(
                'Actions', {}).get(
                    '#VirtualMedia.InsertMedia', {}).get('target', None)
            if inserturl:
                self._do_web_request(inserturl, {'Image': url})
            else:
                try:
                    self._do_web_request(vmurl,
                                         {'Image': url, 'Inserted': True},
                                         'PATCH')
                except exc.RedfishError as re:
                    if re.msgid.endswith(u'PropertyUnknown'):
                        self._do_web_request(vmurl, {'Image': url}, 'PATCH')
                    else:
                        raise
            break
        if suspendedxauth:
                self.wc.stdheaders['X-Auth-Token'] = self.xauthtoken
                if 'Authorization' in self.wc.stdheaders:
                    del self.wc.stdheaders['Authorization']    
        async for res in oem.list_media(self, cache=False):
            pass          

    async def detach_remote_media(self):
        oem = await self.oem()
        try:
            await oem.detach_remote_media()
        except exc.BypassGenericBehavior:
            return
        sysinfo = await self.sysinfo()
        vmcoll = sysinfo.get('VirtualMedia', {}).get('@odata.id', None)
        if not vmcoll:
            bmcinfo = await self._do_web_request(await self.get_bmcurl())
            vmcoll = bmcinfo.get('VirtualMedia', {}).get('@odata.id', None)
        if vmcoll:
            vmlist = await self._do_web_request(vmcoll)
            vmurls = [x['@odata.id'] for x in vmlist.get('Members', [])]
            async for vminfo in self._do_bulk_requests(vmurls):
                vminfo, currl = vminfo
                if vminfo['Image']:
                    ejurl = vminfo.get(
                        'Actions', {}).get(
                            '#VirtualMedia.EjectMedia', {}).get('target', None)
                    if ejurl:
                        await self._do_web_request(ejurl, {})
                    else:
                        try:
                            await self._do_web_request(currl,
                                                       {'Image': None,
                                                        'Inserted': False},
                                                       method='PATCH')
                        except exc.RedfishError as re:
                            if re.msgid.endswith(u'PropertyUnknown'):
                                await self._do_web_request(currl, {'Image': None},
                                                     method='PATCH')
                            else:
                                raise
        oem = await self.oem()
        async for res in oem.list_media(self, cache=False):
            pass

    async def upload_media(self, filename, progress=None, data=None):
        """Upload a file to be hosted on the target BMC

        This will upload the specified data to
        the BMC so that it will make it available to the system as an emulated
        USB device.

        :param filename: The filename to use, the basename of the parameter
                         will be given to the bmc.
        :param progress: Optional callback for progress updates
        """
        oem = await self.oem()
        return await oem.upload_media(filename, progress, data)

    async def get_update_status(self):
        oem = await self.oem()
        return await oem.get_update_status()   

    async def update_firmware(self, file, data=None, progress=None, bank=None, otherfields=()):
        """Send file to BMC to perform firmware update

         :param filename:  The filename to upload to the target BMC
         :param data:  The payload of the firmware.  Default is to read from
                       specified filename.
         :param progress:  A callback that will be given a dict describing
                           update process.  Provide if
         :param bank: Indicate a target 'bank' of firmware if supported
        """
        if progress is None:
            progress = lambda x: True
        oem = await self.oem()
        return await oem.update_firmware(file, data, progress, bank, otherfields)

    async def get_diagnostic_data(self, savefile, progress=None, autosuffix=False):
        if os.path.exists(savefile) and not os.path.isdir(savefile):
            raise exc.InvalidParameterValue(
                'Not allowed to overwrite existing file: {0}'.format(
                    savefile))
        oem = await self.oem()
        return await oem.get_diagnostic_data(savefile, progress, autosuffix)

    async def get_licenses(self):
        oem = await self.oem()
        async for lic in oem.get_licenses(self):
            yield lic

    async def delete_license(self, name):
        oem = await self.oem()
        return await oem.delete_license(name, self)

    async def save_licenses(self, directory):
        if os.path.exists(directory) and not os.path.isdir(directory):
            raise exc.InvalidParameterValue(
                'Not allowed to overwrite existing file: {0}'.format(
                    directory))
        oem = await self.oem()
        async for lic in oem.save_licenses(directory, self):
            yield lic

    async def apply_license(self, filename, progress=None, data=None):
        oem = await self.oem()
        return await oem.apply_license(filename, self, progress, data)

if __name__ == '__main__':
    print(repr(
        Command(sys.argv[1], os.environ['BMCUSER'], os.environ['BMCPASS'],
                verifycallback=lambda x: True).get_power()))
