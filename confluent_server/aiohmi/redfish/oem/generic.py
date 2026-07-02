# Copyright 2019-2022 Lenovo Corporation
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
from fnmatch import fnmatch
import json
import os
import re
import time
import uuid

import base64
import copy
import aiohmi.constants as const
import aiohmi.exceptions as exc
import aiohmi.media as media
import aiohmi.util.webclient as webclient
from aiohmi.util.parse import parse_time
from datetime import datetime
from datetime import timedelta
from dateutil import tz
import socket

def _pem_to_dict(pemdata, uefi=False):
    """Pull PEM into a dict

    Accepts a file-like or a string or bytes.

    A dict with the PEM as a value for CertificateString is created.
    If uefi, then "UefiSignatureOwner" is also created with a random GUID.
    This is how redfish expects certificate information for CAs to be provided for
    UEFI and for itself.
    """
    if hasattr(pemdata, 'read'):
        pemdata = pemdata.read()
    if isinstance(pemdata, bytes):
        pemdata = pemdata.decode('utf-8')
    cert_dict = {
        'CertificateString': pemdata,
        'CertificateType': 'PEM',
        }
    if uefi:
        cert_dict['UefiSignatureOwner'] = str(uuid.uuid4())
    return cert_dict

class SensorReading(object):
    def __init__(self, healthinfo, sensor=None, value=None, units=None,
                 unavailable=False):
        if sensor:
            self.name = sensor['name']
        else:
            self.name = healthinfo['Name']
            self.health = _healthmap.get(healthinfo.get(
                'Status', {}).get('Health', None), const.Health.Warning)
            self.states = [healthinfo.get('Status', {}).get('Health',
                                                            'Unknown')]
            self.health = _healthmap[healthinfo['Status']['Health']]
            self.states = [healthinfo['Status']['Health']]
        self.value = value
        self.state_ids = None
        self.imprecision = None
        self.units = units
        self.unavailable = unavailable


def _to_boolean(attrval):
    attrval = attrval.lower()
    if not attrval:
        return False
    if ('true'.startswith(attrval) or 'yes'.startswith(attrval)
            or 'enabled'.startswith(attrval) or attrval == '1'):
        return True
    if ('false'.startswith(attrval) or 'no'.startswith(attrval)
            or 'disabled'.startswith(attrval) or attrval == '0'):
        return False
    raise Exception(
        'Unrecognized candidate for boolean: {0}'.format(attrval))


def _normalize_mac(mac):
    if ':' not in mac:
        mac = ':'.join((
            mac[:2], mac[2:4], mac[4:6],
            mac[6:8], mac[8:10], mac[10:12]))
    return mac.lower()


_healthmap = {
    'Critical': const.Health.Critical,
    'Unknown': const.Health.Warning,
    'Warning': const.Health.Warning,
    'OK': const.Health.Ok,
}

boot_devices_write = {
    'net': 'Pxe',
    'network': 'Pxe',
    'pxe': 'Pxe',
    'hd': 'Hdd',
    'usb': 'Usb',
    'cd': 'Cd',
    'cdrom': 'Cd',
    'optical': 'Cd',
    'dvd': 'Cd',
    'floppy': 'Floppy',
    'default': 'None',
    'setup': 'BiosSetup',
    'bios': 'BiosSetup',
    'f1': 'BiosSetup',
    'http': 'UefiHttp',
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


class AttrDependencyHandler(object):
    def __init__(self, dependencies, currsettings, pendingsettings):
        self.dependencymap = {}
        for dep in dependencies.get('Dependencies', [{}]):
            if 'Dependency' not in dep:
                continue
            if dep['Type'] != 'Map':
                continue
            if dep['DependencyFor'] in self.dependencymap:
                self.dependencymap[
                    dep['DependencyFor']].append(dep['Dependency'])
            else:
                self.dependencymap[
                    dep['DependencyFor']] = [dep['Dependency']]
        self.curr = currsettings
        self.pend = pendingsettings
        self.reg = dependencies['Attributes']

    def get_overrides(self, setting):
        overrides = {}
        blameattrs = []
        if setting not in self.dependencymap:
            return {}, []
        for depinfo in self.dependencymap[setting]:
            lastoper = None
            lastcond = None
            for mapfrom in depinfo.get('MapFrom', []):
                if lastcond is not None and not lastoper:
                    break  # MapTerm required to make sense of this, give up
                currattr = mapfrom['MapFromAttribute']
                blameattrs.append(currattr)
                currprop = mapfrom['MapFromProperty']
                if currprop == 'CurrentValue':
                    if currattr in self.pend:
                        currval = self.pend[currattr]
                    elif currattr in self.curr:
                        currval = self.curr[currattr]
                    else:
                        break  # The cited dependency attribute is missing, can't enforce
                               # requested override                    
                else:
                    currval = self.reg[currattr][currprop]
                lastcond = self.process(currval, mapfrom, lastcond, lastoper)
                lastoper = mapfrom.get('MapTerms', None)
            if lastcond:
                if setting not in overrides:
                    overrides[setting] = {}
                if depinfo['MapToAttribute'] not in overrides[setting]:
                    overrides[depinfo['MapToAttribute']] = {}
                overrides[depinfo['MapToAttribute']][
                    depinfo['MapToProperty']] = depinfo['MapToValue']
        return overrides, blameattrs

    def process(self, currval, mapfrom, lastcond, lastoper):
        newcond = None
        mfc = mapfrom['MapFromCondition']
        if mfc == 'EQU':
            newcond = currval == mapfrom['MapFromValue']
        if mfc == 'NEQ':
            newcond = currval != mapfrom['MapFromValue']
        if mfc == 'GEQ':
            newcond = float(currval) >= float(mapfrom['MapFromValue'])
        if mfc == 'GTR':
            newcond = float(currval) > float(mapfrom['MapFromValue'])
        if mfc == 'LEQ':
            newcond = float(currval) <= float(mapfrom['MapFromValue'])
        if mfc == 'LSS':
            newcond = float(currval) < float(mapfrom['MapFromValue'])
        if lastcond is not None:
            if lastoper == 'AND':
                return lastcond and newcond
            elif lastoper == 'OR':
                return lastcond or newcond
            return None
        return newcond


class OEMHandler(object):
    hostnic = None
    usegenericsensors = True
    def _invalidate_url_cache(self, url):
        if url is None:
            return
        if url in self._urlcache:
            del self._urlcache[url]
        if url + '?$expand=.' in self._urlcache:
            del self._urlcache[url + '?$expand=.']
    
    @classmethod
    async def create(cls, sysinfo, sysurl, webclient, cache, gpool=None, rootinfo={}):
        self = cls()
        self._gpool = gpool
        self._varsysinfo = sysinfo
        self._varsysurl = sysurl
        self._varbmcurl = None
        self._urlcache = cache
        self.webclient = webclient
        self._hwnamemap = {}
        self._rootinfo = rootinfo
        if not self._rootinfo:
            self._rootinfo = await self.webclient.grab_json_response(
                '/redfish/v1/')
        self._varbmcurl = None
        self._varsysurl = sysurl        
        self._allsysurls = []
        if sysurl is None:  # generic means we need to gather all systems
            if 'Systems' in self._rootinfo:
                systems = self._rootinfo['Systems']['@odata.id']
                res = await self.webclient.grab_json_response_with_status(systems)
                if res[1] == 200:
                    members = res[0]['Members']
                    for system in members:
                        if system['@odata.id'] != sysurl:
                            self._allsysurls.append(system['@odata.id'])
        else:
            self._allsysurls = [sysurl]
        return self

    async def get_screenshot(self, outfile):
        raise exc.UnsupportedFunctionality(
            'Retrieving screenshot is not implemented for this platform')

    async def get_default_mgrurl(self):
        if not self._varbmcurl and 'Managers' in self._rootinfo:
            bmcoll = self._rootinfo['Managers']['@odata.id']
            res = await self.webclient.grab_json_response_with_status(bmcoll)
            if res[1] == 401:
                raise exc.PyghmiException('Access Denied')
            elif res[1] < 200 or res[1] >= 300:
                raise exc.PyghmiException(repr(res[0]))
            bmcs = res[0]['Members']
            if len(bmcs) == 1:
                self._varbmcurl = bmcs[0]['@odata.id']
        return self._varbmcurl
    
    async def get_default_sysurl(self):
        if not self._varsysurl and 'Systems' in self._rootinfo:
            systems = self._rootinfo['Systems']['@odata.id']
            res = await self.webclient.grab_json_response_with_status(systems)
            if res[1] == 401:
                raise exc.PyghmiException('Access Denied')
            elif res[1] < 200 or res[1] >= 300:
                raise exc.PyghmiException(repr(res[0]))
            members = res[0]
            systems = members['Members']
            if self._varsysurl:
                for system in systems:
                    if system['@odata.id'] == self._varsysurl or system['@odata.id'].split('/')[-1] == self._varsysurl:
                        self._varsysurl = system['@odata.id']
                        break
                else:
                    raise exc.PyghmiException(
                        'Specified sysurl not found: {0}'.format(self._varsysurl))
            else:
                if len(systems) > 1:
                    systems = [x for x in systems if 'DPU' not in x['@odata.id']]
                if len(systems) > 1:
                    raise exc.PyghmiException(
                        'Multi system manager, sysurl is required parameter')
                if len(systems):
                    self._varsysurl = systems[0]['@odata.id']
                else:
                    self._varsysurl = None
        return self._varsysurl


    async def supports_expand(self, url):
        # Unfortunately, the state of expand in redfish is pretty dicey,
        # so an OEM handler must opt into this behavior
        # There is a way an implementation advertises support, however
        # this isn't to be trusted.
        # Even among some generally reputable implementations, they will fail in some scenarios
        # and you'll see in their documentation "some urls will fail if you try to expand them"
        # perhaps being specific, but other times being vague, but in either case,
        # nothing programattic to consume to know when to do or not do an expand..
        return False

    async def get_system_power_watts(self, fishclient):
        totalwatts = 0
        gotpower = False
        sysinfo = await fishclient.sysinfo()
        for chassis in sysinfo.get('Links', {}).get('Chassis', []):
            envinfo = await fishclient._get_chassis_env(chassis)
            currwatts = envinfo.get('watts', None)
            if currwatts is not None:
                gotpower = True
                totalwatts += envinfo['watts']
        if not gotpower:
            raise exc.UnsupportedFunctionality("System does not provide Power under redfish EnvironmentMetrics")
        return totalwatts

    async def _get_cpu_temps(self, fishclient):
        cputemps = []
        sysinfo = await fishclient.sysinfo()
        for chassis in sysinfo.get('Links', {}).get('Chassis', []):
            thermals = await fishclient._get_thermals(chassis)
            for temp in thermals:
                if temp.get('PhysicalContext', '') != 'CPU':
                    continue
                if temp.get('ReadingCelsius', None) is None:
                    continue
                cputemps.append(temp)
        return cputemps

    
    async def get_bmcurl(self):
        if not self._varbmcurl:
            self._varbmcurl = (await self.sysinfo()).get('Links', {}).get(
                'ManagedBy', [{}])[0].get('@odata.id', None)
        return self._varbmcurl

    
    async def sysinfo(self):
        sysurl = await self.get_default_sysurl()
        return await self._do_web_request(sysurl)
    
    async def get_bmc_csr(self, keytype=None, keylength=None, cn=None, city=None,
                    state=None, country=None, org=None, orgunit=None):
        # A fun time here, the redfish specification is weird about this.
        # We have a certificateservice, sounds good, and an action to generate a CSR,
        # straightforward enough, but you have to indicate a certificate collection...
        # We get a list of locations, so we have to infer the collection, which
        # is perhaps odd, but a relatively safe bet.
        # However, the purpose of the certificates is opaque, so we can only guess
        # based on strings in the url if there is ambiguity.
        rootinfo = await self._do_web_request('/redfish/v1/')
        certserviceurl = rootinfo.get('CertificateService', {}).get('@odata.id', None)
        if not certserviceurl:
            raise exc.PyghmiException('No CertificateService found on platform')
        certservice = await self._do_web_request(certserviceurl)
        gencsractinfo = certservice.get('Actions', {}).get("#CertificateService.GenerateCSR", {})
        curveids = gencsractinfo.get('KeyCurveId@Redfish.AllowableValues', [])
        keylens = gencsractinfo.get('KeyBitLength@Redfish.AllowableValues', [])
        keypairalgorithms = gencsractinfo.get('KeyPairAlgorithm@Redfish.AllowableValues', [])
        selectedcurve = None
        selectedkeylen = None
        selectedkpa = None
        if not keytype:
            for kpa in keypairalgorithms:
                if 'ECDH' in kpa:
                    keytype = 'ECC'
                    selectedkpa = kpa
                    break
                if 'RSA' in kpa:
                    selectedkpa = kpa
                    keytype = 'RSA'
        if not keytype:
            raise exc.PyghmiException('No valid key type found for CSR generation')
        if keytype.upper() in ('ECC', 'ECDSA'):
            if not curveids:
                raise exc.PyghmiException('No valid curves found for ECC/ECDSA key type')
            if keylength:
                for curve in curveids:
                    if fnmatch(curve, '*{0}'.format(keylength)):
                        selectedcurve = curve
                        break
            else:
                selectedcurve = curveids[-1]
        elif keytype.upper() == 'RSA':
            if not keylens:
                raise exc.PyghmiException('No valid key lengths found for RSA key type')
            if keylength:
                allkeylens = []
                for klp in keylens:
                    if isinstance(klp, int):
                        allkeylens.append(klp)
                        continue
                    for kl in klp.split(':'):
                        allkeylens.append(int(kl))
                if keylength not in allkeylens:
                    raise exc.PyghmiException('Requested key length {0} not supported'.format(keylength))
                selectedkeylen = keylength
        gencsrtarg = gencsractinfo.get('target', None)
        certcoll = await self.get_certificate_collection(certservice)
        payload = {
            'CertificateCollection': {"@odata.id": certcoll},
            'City': city or 'Unspecified',
            'CommonName': cn or self.webclient.thehost,
            'Country': country or 'AQ',  # Need *a* valid two letter country code, Antarctica is more equally likely to be wrong than most.
            'Organization': org or 'Unspecified',
            'State': state or 'Unspecified',
        }
        if orgunit:
            payload['OrganizationalUnit'] = orgunit
        if selectedcurve:
            payload['KeyCurveId'] = selectedcurve
        elif selectedkeylen:
            payload['KeyLength'] = selectedkeylen
        if selectedkpa:
            payload['KeyPairAlgorithm'] = selectedkpa
        rsp = await self._do_web_request(gencsrtarg, payload)
        csr = rsp.get('CSRString', None)
        return csr

    async def get_certificate_collection(self, certservice):
        certcollections = set([])
        certlocs = certservice.get('CertificateLocations', {}).get('@odata.id', None)
        if certlocs:
            certlocdata = await self._do_web_request(certlocs)
            for cert in certlocdata.get('Links', {}).get('Certificates', []):
                certurl = cert.get('@odata.id', None)
                if not certurl:
                    continue
                # we need to remove the last part of url to get collection
                collurl = '/'.join(certurl.split('/')[:-1])
                certcollections.add(collurl)
        if len(certcollections) == 0:
            raise exc.PyghmiException('No certificate collections found for certificate operation')
        if len(certcollections) > 1:
            for candcoll in list(certcollections):
                if 'TrustedCertificates' in candcoll:  # likely a CA store
                    certcollections.discard(candcoll)
                elif 'LDAP' in candcoll:  # certificate for LDAP server
                    certcollections.discard(candcoll)
                elif 'KMIP' in candcoll:  # not for TLS
                    certcollections.discard(candcoll)
                elif 'Boot/Certificates' in candcoll:
                    certcollections.discard(candcoll)                
        if len(certcollections) > 1:
            raise exc.PyghmiException('Multiple certificate collections found, unable to infer intended target for certificate operation')
        certcoll = list(certcollections)[0]
        return certcoll

    async def install_bmc_certificate(self, certdata):
        rootinfo = await self._do_web_request('/redfish/v1/')
        certserviceurl = rootinfo.get('CertificateService', {}).get('@odata.id', None)
        if not certserviceurl:
            raise exc.PyghmiException('No CertificateService found on platform')
        certservice = await self._do_web_request(certserviceurl)
        certlocs = certservice.get('CertificateLocations', {}).get('@odata.id', None)
        if not certlocs:
            raise exc.PyghmiException('No CertificateLocations found on platform')
        certlocdata = await self._do_web_request(certlocs)
        allcerts = set([])
        for certloc in certlocdata.get('Links', {}).get('Certificates', []):
            certurl = certloc.get('@odata.id', None)
            if not certurl:
                continue
            allcerts.add(certurl)
        if len(allcerts) == 0:
            raise exc.PyghmiException('No Certificates found on platform')
        elif len(allcerts) > 1:
            # try to narrow down to server cert
            for certurl in list(allcerts):
                if 'TrustedCertificates' in certurl:
                    allcerts.discard(certurl)
                elif 'LDAP' in certurl:
                    allcerts.discard(certurl)
                elif 'KMIP' in certurl:
                    allcerts.discard(certurl)
                elif 'Boot/Certificates' in certurl:
                    allcerts.discard(certurl)                
        if len(allcerts) > 1:
            raise exc.PyghmiException('Multiple Certificates found, unable to infer intended target for certificate installation')
        targcerturl = list(allcerts)[0]
        replacecerturl = certservice.get('Actions', {}).get(
            '#CertificateService.ReplaceCertificate', {}).get('target', None)
        certpayload = _pem_to_dict(certdata)
        certpayload['CertificateUri'] = {'@odata.id': targcerturl}
        #/redfish/v1/CertificateService/Actions/CertificateService.ReplaceCertificate
        await self._do_web_request(replacecerturl, certpayload)

    async def add_trusted_ca(self, pemdata):
        mgrinfo = await self._do_web_request(await self.get_bmcurl())
        secpolicy = mgrinfo.get('SecurityPolicy', {}).get('@odata.id', None)
        if secpolicy:
            secinfo = await self._do_web_request(secpolicy)
            certcoll = secinfo.get('TLS', {}).get('Client', {}).get('TrustedCertificates', {}).get('@odata.id', None)
            self._invalidate_url_cache(certcoll)
            if certcoll:
                certpayload = _pem_to_dict(pemdata)
                await self._do_web_request(certcoll, certpayload)
                self._invalidate_url_cache(certcoll)
                return True
        raise exc.PyghmiException('Platform does not support adding trusted CAs')

    async def del_trusted_ca(self, certid):
        mgrinfo = await self._do_web_request(await self.get_bmcurl())
        secpolicy = mgrinfo.get('SecurityPolicy', {}).get('@odata.id', None)
        if secpolicy:
            secinfo = await self._do_web_request(secpolicy)
            certcoll = secinfo.get('TLS', {}).get('Client', {}).get('TrustedCertificates', {}).get('@odata.id', None)
            self._invalidate_url_cache(certcoll)
            if certcoll:
                certs = await self._get_expanded_data(certcoll)
                certs = certs.get('Members', [])
                for cert in certs:
                    if cert.get('Id', '') == certid:
                        await self._do_web_request(cert['@odata.id'], method='DELETE')
                        self._invalidate_url_cache(certcoll)
                        return True
        raise exc.PyghmiException(f'No such certificate found: {certid}')

    async def get_trusted_cas(self):
        mgrinfo = await self._do_web_request(await self.get_bmcurl())
        secpolicy = mgrinfo.get('SecurityPolicy', {}).get('@odata.id', None)
        if secpolicy:
            secinfo = await self._do_web_request(secpolicy)
            certcoll = secinfo.get('TLS', {}).get('Client', {}).get('TrustedCertificates', {}).get('@odata.id', None)
            if certcoll:
                certs = await self._get_expanded_data(certcoll)
                certs = certs.get('Members', [])
                for cert in certs:
                    certdesc = {
                        'id': cert.get('Id', ''),
                        'name': cert.get('Name', ''),
                        'pem': cert.get('CertificateString', None),
                        'subject': cert.get('Subject', {}).get('CommonName', ''),
                        'sans': cert.get('Subject', {}).get('AlternativeNames', []),
                        'issuer': cert.get('Issuer', {}).get('CommonName', ''),
                        'validfrom': cert.get('ValidNotBefore', ''),
                        'validto': cert.get('ValidNotAfter', ''),
                    }
                    yield certdesc

    async def get_event_log(self, clear=False, fishclient=None, extraurls=[]):
        bmcinfo = await self._do_web_request(await fishclient.get_bmcurl())
        lsurl = bmcinfo.get('LogServices', {}).get('@odata.id', None)
        if not lsurl:
            return
        currtime = bmcinfo.get('DateTime', None)
        correction = timedelta(0)
        utz = tz.tzoffset('', 0)
        ltz = tz.gettz()
        if currtime:
            currtime = parse_time(currtime)
        if currtime:
            now = datetime.now(utz)
            try:
                correction = now - currtime
            except TypeError:
                correction = now - currtime.replace(tzinfo=utz)
        lurls = (await self._do_web_request(lsurl)).get('Members', [])
        lurls.extend(extraurls)
        for lurl in lurls:
            lurl = lurl['@odata.id']
            try:
                loginfo = await self._do_web_request(lurl, cache=(not clear))
            except Exception:
                record = {}
                record['log_id'] = os.path.basename(lurl)
                record['message'] = 'Could not retrieve log at {0}'.format(lurl)
                record['severity'] = const.Health.Ok
                record['timestamp'] = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
                yield record
                continue
            loginfo = await self._do_web_request(lurl, cache=(not clear))
            entriesurl = loginfo.get('Entries', {}).get('@odata.id', None)
            if not entriesurl:
                continue
            logid = loginfo.get('Id', '')
            entries = await self._do_web_request(entriesurl, cache=False)
            if clear:
                # The clear is against the log service etag, not entries
                # so we have to fetch service etag after we fetch entries
                # until we can verify that the etag is consistent to prove
                # that the clear is atomic
                newloginfo = await self._do_web_request(lurl, cache=False)
                clearurl = newloginfo.get('Actions', {}).get(
                    '#LogService.ClearLog', {}).get('target', '')
                while clearurl:
                    try:
                        await self._do_web_request(clearurl, method='POST',
                                            payload={})
                        clearurl = False
                    except exc.PyghmiException as e:
                        if 'EtagPreconditionalFailed' not in str(e):
                            raise
                        # This doesn't guarantee atomicity, but it mitigates
                        # greatly.  Unfortunately some implementations
                        # mutate the tag endlessly and we have no hope
                        entries = await self._do_web_request(entriesurl, cache=False)
                        newloginfo = await self._do_web_request(lurl, cache=False)
            for log in entries.get('Members', []):
                if ('Created' not in log and 'Message' not in log
                        and 'Severity' not in log):
                    # without any data, this log entry isn't actionable
                    continue
                record = {}
                record['log_id'] = logid
                parsedtime = parse_time(log.get('Created', ''))
                if not parsedtime:
                    parsedtime = parse_time(log.get('EventTimestamp', ''))
                if parsedtime:
                    entime = parsedtime + correction
                    entime = entime.astimezone(ltz)
                    record['timestamp'] = entime.strftime('%Y-%m-%dT%H:%M:%S')
                else:
                    record['timestamp'] = log.get('Created', '')
                record['message'] = log.get('Message', None)
                record['severity'] = _healthmap.get(
                    log.get('Severity', 'Warning'), const.Health.Ok)
                yield record

    async def get_average_processor_temperature(self, fishclient):
        cputemps = await self._get_cpu_temps(fishclient)
        if not cputemps:
            return SensorReading(
            None, {'name': 'Average Processor Temperature'}, value=None, units='°C',
                   unavailable=True)
        cputemps = [x['ReadingCelsius'] for x in cputemps]
        avgtemp = sum(cputemps) / len(cputemps)
        return SensorReading(
            None, {'name': 'Average Processor Temperature'}, value=avgtemp, units='°C')


    async def get_health(self, fishclient, verbose=True):
        sysinfo = await self.sysinfo()
        health = sysinfo.get('Status', {})
        health = health.get('HealthRollup', health.get('Health', 'Unknown'))
        warnunknown = health == 'Unknown'
        health = _healthmap[health]
        summary = {'badreadings': [], 'health': health}
        if health > 0 and verbose:
            # now have to manually peruse all psus, fans, processors, ram,
            # storage
            procsumstatus = sysinfo.get('ProcessorSummary', {}).get(
                'Status', {})
            procsumstatus = procsumstatus.get('HealthRollup',
                                              procsumstatus.get('Health',
                                                                'OK'))
            if procsumstatus != 'OK':
                procfound = False
                procurl = sysinfo.get('Processors', {}).get('@odata.id',
                                                          None)
                if procurl:
                    for cpu in await fishclient._do_web_request(procurl).get(
                            'Members', []):
                        cinfo = await fishclient._do_web_request(cpu['@odata.id'])
                        if cinfo.get('Status', {}).get(
                                'State', None) == 'Absent':
                            continue
                        if cinfo.get('Status', {}).get(
                                'Health', None) not in ('OK', None):
                            procfound = True
                            summary['badreadings'].append(SensorReading(cinfo))
                if not procfound:
                    procinfo = sysinfo['ProcessorSummary']
                    procinfo['Name'] = 'Processors'
                    summary['badreadings'].append(SensorReading(procinfo))
            memsumstatus = sysinfo.get(
                'MemorySummary', {}).get('Status', {})
            memsumstatus = memsumstatus.get('HealthRollup',
                                            memsumstatus.get('Health', None))
            if memsumstatus != 'OK':
                dimmfound = False
                dimmdata = await self._get_mem_data()
                for dimminfo in dimmdata:
                    if dimminfo.get('Status', {}).get(
                            'State', None) == 'Absent':
                        continue
                    if dimminfo.get('Status', {}).get(
                            'Health', None) not in ('OK', None):
                        summary['badreadings'].append(SensorReading(dimminfo))
                        dimmfound = True
                if not dimmfound:
                    meminfo = sysinfo['MemorySummary']
                    meminfo['Name'] = 'Memory'
                    summary['badreadings'].append(SensorReading(meminfo))
            for adapter in sysinfo['PCIeDevices']:
                adpinfo = await fishclient._do_web_request(adapter['@odata.id'])
                if adpinfo['Status']['Health'] not in ('OK', None):
                    summary['badreadings'].append(SensorReading(adpinfo))
            for fun in sysinfo['PCIeFunctions']:
                funinfo = await fishclient._do_web_request(fun['@odata.id'])
                if funinfo['Status']['Health'] not in ('OK', None):
                    summary['badreadings'].append(SensorReading(funinfo))
        if warnunknown and not summary['badreadings']:
            unkinf = SensorReading({'Name': 'BMC',
                                    'Status': {'Health': 'Unknown'}})
            unkinf.states = ['System does not provide health information']
            summary['badreadings'].append(unkinf)
        return summary

    async def user_delete(self, uid, fishclient):
        # Redfish doesn't do so well with Deleting users either...
        # Blanking the username seems to be the convention
        # First, set a bogus password in case the implementation does honor
        # blank user, at least render such an account harmless
        try:
            accinfo = await fishclient._account_url_info_by_id(uid)
            if not accinfo:
                raise Exception("No such account found")
            await self._do_web_request(accinfo[0], method='DELETE')
        except Exception: # fall back to old ipmi-like behavior for such implementations
            await fishclient.set_user_password(uid, base64.b64encode(os.urandom(15)))
            await fishclient.set_user_name(uid, '')        
        return True

    async def set_bootdev(self, bootdev, persist=False, uefiboot=None,
                    fishclient=None):
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
        reqbootdev = bootdev
        if (bootdev not in boot_devices_write
                and bootdev not in boot_devices_read):
            raise exc.InvalidParameterValue('Unsupported device %s'
                                            % repr(bootdev))
        bootdev = boot_devices_write.get(bootdev, bootdev)
        if bootdev == 'UefiHttp':  # not universally supported, remap to Pxe
            sysinfo = await self.sysinfo()
            allowed = sysinfo.get('Boot', {}).get('BootSourceOverrideTarget@Redfish.AllowableValues', [])
            if 'UefiHttp' not in allowed:
                bootdev = 'Pxe'
        if bootdev == 'None':
            payload = {'Boot': {'BootSourceOverrideEnabled': 'Disabled'}}
        else:
            payload = {'Boot': {
                'BootSourceOverrideEnabled': 'Continuous' if persist
                                             else 'Once',
                'BootSourceOverrideTarget': bootdev,
            }}
            if uefiboot is not None:
                uefiboot = 'UEFI' if uefiboot else 'Legacy'
                payload['Boot']['BootSourceOverrideMode'] = uefiboot
                try:
                    await fishclient._do_web_request(fishclient.sysurl, payload,
                                               method='PATCH', etag='*')
                    return {'bootdev': reqbootdev}
                except Exception:
                    del payload['Boot']['BootSourceOverrideMode']
            else:
                payload['Boot']['BootSourceOverrideMode'] = 'UEFI'
        #thetag = fishclient.sysinfo.get('@odata.etag', None)
        await fishclient._do_web_request(fishclient.sysurl, payload, method='PATCH',
                                   etag='*') # thetag)
        return {'bootdev': reqbootdev}

    def _get_cache(self, url):
        now = os.times()[4]
        cachent = self._urlcache.get(url, None)
        if cachent and cachent['vintage'] > now - 30:
            return cachent['contents']
        return None

    async def get_bmc_configuration(self):
        return {}

    async def set_bmc_configuration(self, changeset):
        raise exc.UnsupportedFunctionality(
            'Platform does not support setting bmc attributes')

    async def _get_biosreg(self, url, fishclient):
        addon = {}
        valtodisplay = {}
        displaytoval = {}
        reg = await fishclient._do_web_request(url)
        reg = reg['RegistryEntries']
        for attr in reg['Attributes']:
            vals = attr.get('Value', [])
            if vals:
                valtodisplay[attr['AttributeName']] = {}
                displaytoval[attr['AttributeName']] = {}
                for val in vals:
                    valtodisplay[
                        attr['AttributeName']][val['ValueName']] = val[
                            'ValueDisplayName']
                    displaytoval[
                        attr['AttributeName']][val['ValueDisplayName']] = val[
                            'ValueName']
            defaultval = attr.get('DefaultValue', None)
            defaultval = valtodisplay.get(attr['AttributeName'], {}).get(
                defaultval, defaultval)
            if attr['Type'] == 'Integer' and defaultval:
                defaultval = int(defaultval)
            if attr['Type'] == 'Boolean':
                vals = [{'ValueDisplayName': 'True'},
                        {'ValueDisplayName': 'False'}]
            addon[attr['AttributeName']] = {
                'default': defaultval,
                'help': attr.get('HelpText', None),
                'sortid': attr.get('DisplayOrder', None),
                'possible': [x['ValueDisplayName'] for x in vals],
            }
        return addon, valtodisplay, displaytoval, reg

    async def get_system_configuration(self, hideadvanced=True, fishclient=None):
        return (await self._getsyscfg(fishclient))[0]

    async def _get_attrib_registry(self, fishclient, attribreg):
        overview = await fishclient._do_web_request('/redfish/v1/')
        reglist = overview['Registries']['@odata.id']
        reglist = await fishclient._do_web_request(reglist)
        regurl = None
        for cand in reglist.get('Members', []):
            cand = cand.get('@odata.id', '')
            candname = cand.split('/')[-1]
            if candname == '':  # implementation uses trailing slash
                candname = cand.split('/')[-2]
            if candname == attribreg:
                regurl = cand
                break
        if not regurl:
            # Workaround a vendor bug where they link to a
            # non-existant name
            for cand in reglist.get('Members', []):
                cand = cand.get('@odata.id', '')
                candname = cand.split('/')[-1]
                candname = candname.split('.')[0]
                if candname == attribreg.split('.')[0]:
                    regurl = cand
                    break
        if regurl:
            reginfo = await fishclient._do_web_request(regurl)
            for reg in reginfo.get('Location', []):
                if reg.get('Language', 'en').startswith('en'):
                    reguri = reg['Uri']
                    reginfo = await self._get_biosreg(reguri, fishclient)
                    return reginfo
                    extrainfo, valtodisplay, _, self.attrdeps = reginfo


    async def _getsyscfg(self, fishclient):
        biosurl = await fishclient.get_biosurl()
        biosinfo = await self._do_web_request(biosurl, cache=False)
        reginfo = ({}, {}, {}, {})
        extrainfo = {}
        valtodisplay = {}
        self.attrdeps = {'Dependencies': [], 'Attributes': []}
        if 'AttributeRegistry' in biosinfo:
            reginfo = await self._get_attrib_registry(fishclient, biosinfo['AttributeRegistry'])
            if reginfo:
                extrainfo, valtodisplay, _, self.attrdeps = reginfo
        currsettings = {}
        try:
            pendingsettings = await fishclient._do_web_request(
                await fishclient.get_setbiosurl())
        except exc.UnsupportedFunctionality:
            pendingsettings = {}
        pendingsettings = pendingsettings.get('Attributes', {})
        for setting in biosinfo.get('Attributes', {}):
            val = biosinfo['Attributes'][setting]
            currval = val
            if setting in pendingsettings:
                val = pendingsettings[setting]
            val = valtodisplay.get(setting, {}).get(val, val)
            currval = valtodisplay.get(setting, {}).get(currval, currval)
            val = {'value': val}
            if currval != val['value']:
                val['active'] = currval
            val.update(**extrainfo.get(setting, {}))
            currsettings[setting] = val
        return currsettings, reginfo

    async def set_system_configuration(self, changeset, fishclient):
        while True:
            try:
                await self._set_system_configuration(changeset, fishclient)
                return
            except exc.RedfishError as re:
                if ('etag' not in re.msgid.lower()
                        and 'PreconditionFailed' not in re.msgid):
                    raise

    async def _set_system_configuration(self, changeset, fishclient):
        currsettings, reginfo = await self._getsyscfg(fishclient)
        biosurl = await fishclient.get_biosurl()
        rawsettings = await fishclient._do_web_request(biosurl,
                                                 cache=False)
        rawsettings = rawsettings.get('Attributes', {})
        setbiosurl = await fishclient.get_setbiosurl()
        pendingsettings = await fishclient._do_web_request(
            setbiosurl)
        return await self._set_redfish_settings(
            changeset, fishclient, currsettings, rawsettings,
            pendingsettings, self.attrdeps, reginfo,
            setbiosurl)

    async def _set_redfish_settings(self, inchangeset, fishclient, currsettings,                      
                              rawsettings, pendingsettings, attrdeps, reginfo,
                              seturl):

        etag = pendingsettings.get('@odata.etag', None)
        pendingsettings = pendingsettings.get('Attributes', {})
        dephandler = AttrDependencyHandler(attrdeps, rawsettings,
                                           pendingsettings)
        changeset = copy.deepcopy(inchangeset)
        for change in list(changeset):
            if change not in currsettings:
                found = False
                for attr in currsettings:
                    if fnmatch(attr.lower(), change.lower()):
                        found = True
                        changeset[attr] = changeset[change]
                    if fnmatch(attr.lower(),
                               change.replace('.', '_').lower()):
                        found = True
                        changeset[attr] = changeset[change]
                if found:
                    del changeset[change]
        for change in changeset:
            changeval = changeset[change]
            overrides, blameattrs = dephandler.get_overrides(change)
            meta = {}
            for attr in attrdeps['Attributes']:
                if attr['AttributeName'] == change:
                    meta = dict(attr)
                    break
            meta.update(**overrides.get(change, {}))
            if meta.get('ReadOnly', False) or meta.get('GrayOut', False):
                errstr = '{0} is read only'.format(change)
                if blameattrs:
                    errstr += (' due to one of the following settings: '
                               '{0}'.format(','.join(sorted(blameattrs)))
                               )
                raise exc.InvalidParameterValue(errstr)
            if (currsettings.get(change, {}).get('possible', [])
                    and changeval not in currsettings[change]['possible']):
                normval = changeval.lower()
                normval = re.sub(r'\s+', ' ', normval)
                if not normval.endswith('*'):
                    normval += '*'
                for cand in currsettings[change]['possible']:
                    if fnmatch(cand.lower().replace(' ', ''),
                               normval.replace(' ', '')):
                        changeset[change] = cand
                        break
                else:
                    raise exc.InvalidParameterValue(
                        '{0} is not a valid value for {1} ({2})'.format(
                            changeval, change, ','.join(
                                currsettings[change]['possible'])))
            if changeset[change] in reginfo[2].get(change, {}):
                changeset[change] = reginfo[2][change][changeset[change]]
            for regentry in reginfo[3].get('Attributes', []):
                if change in (regentry.get('AttributeName', ''),
                              regentry.get('DisplayName', '')):
                    if regentry.get('Type', None) == 'Integer':
                        changeset[change] = int(changeset[change])
                    if regentry.get('Type', None) == 'Boolean':
                        changeset[change] = _to_boolean(changeset[change])
        redfishsettings = {'Attributes': changeset}
        await fishclient._do_web_request(
           seturl, redfishsettings, 'PATCH', etag=etag)

    async def attach_remote_media(self, url, username, password, vmurls):
        return None

    async def detach_remote_media(self):
        return None

    async def get_description(self):
        sysinfo = await self.sysinfo()
        for chassis in sysinfo.get('Links', {}).get('Chassis', []):
            chassisurl = chassis['@odata.id']
            chassisinfo = await self._do_web_request(chassisurl)
            hmm = chassisinfo.get('HeightMm', None)
            if hmm:
                return {'height': hmm/44.45}
        return {}

    def _extract_fwinfo(self, inf):
        return {}

    def get_firmware_inventory(self, components, fishclient, category=None):
        return []

    def set_credentials(self, username, password):
        try:
            self.username = username.decode('utf-8')
        except AttributeError:
            self.username = username
        try:
            self.password = password.decode('utf-8')
        except AttributeError:
            self.password = password

    async def list_media(self, fishclient, cache=True):
        bmcurl = await fishclient.get_bmcurl()
        bmcinfo = await fishclient._do_web_request(bmcurl, cache=cache)
        vmcoll = bmcinfo.get('VirtualMedia', {}).get('@odata.id', None)
        if vmcoll:
            vmlist = await fishclient._do_web_request(vmcoll, cache=cache)
            vmurls = [x['@odata.id'] for x in vmlist.get('Members', [])]
            async for vminfo in fishclient._do_bulk_requests(vmurls, cache=cache):
                vminfo = vminfo[0]
                if vminfo.get('Image', None):
                    imageurl = vminfo['Image'].replace(
                        '/' + vminfo['ImageName'], '')
                    yield media.Media(vminfo['ImageName'], imageurl)
                elif vminfo.get('Inserted', None) and vminfo.get(
                        'ImageName', None):
                    yield media.Media(vminfo['ImageName'])

    async def get_inventory_descriptions(self, withids=False):
        yield "System"
        self._hwnamemap = {}
        async for cpu in self._get_cpu_inventory(True, withids):
            yield cpu
        async for mem in self._get_mem_inventory(True, withids):
            yield mem
        async for adp in self._get_adp_inventory(True, withids):
            yield adp

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
        return nodeinfo

    async def get_inventory_of_component(self, component):
        if component.lower() == 'system':
            nodeinfo = await self._get_node_info()
            sysinfo = {
                'UUID': nodeinfo.get('UUID', '').lower(),
                'Serial Number': nodeinfo.get('SerialNumber', ''),
                'Manufacturer': nodeinfo.get('Manufacturer', ''),
                'Product name': nodeinfo.get('Model', ''),
                'Model': nodeinfo.get(
                    'SKU', nodeinfo.get('PartNumber', '')),
            }
            if sysinfo['UUID'] and '-' not in sysinfo['UUID']:
                sysinfo['UUID'] = '-'.join((
                    sysinfo['UUID'][:8], sysinfo['UUID'][8:12],
                    sysinfo['UUID'][12:16], sysinfo['UUID'][16:20],
                    sysinfo['UUID'][20:]))
            sysinfo['UUID'] = sysinfo['UUID'].lower()

            return sysinfo
        else:
            async for invpair in self.get_inventory():
                if invpair[0].lower() == component.lower():
                    return invpair[1]

    async def get_inventory(self, withids=False):
        sysinfo = {
            'UUID': self._varsysinfo.get('UUID', ''),
            'Serial Number': self._varsysinfo.get('SerialNumber', ''),
            'Manufacturer': self._varsysinfo.get('Manufacturer', ''),
            'Product name': self._varsysinfo.get('Model', ''),
            'Model': self._varsysinfo.get(
                'SKU', self._varsysinfo.get('PartNumber', '')),
        }
        if sysinfo['UUID'] and '-' not in sysinfo['UUID']:
            sysinfo['UUID'] = '-'.join((
                sysinfo['UUID'][:8], sysinfo['UUID'][8:12],
                sysinfo['UUID'][12:16], sysinfo['UUID'][16:20],
                sysinfo['UUID'][20:]))
        sysinfo['UUID'] = sysinfo['UUID'].lower()
        yield ('System', sysinfo)
        self._hwnamemap = {}
        adpurls = await self._get_adp_urls()
        diskurls = await self._get_disk_urls()
        allurls = adpurls + diskurls
        list([x async for x in self._do_bulk_requests(allurls)])
        async for cpu in self._get_cpu_inventory(withids=withids):
            yield cpu
        async for mem in self._get_mem_inventory(withids=withids):
            yield mem
        async for adp in self._get_adp_inventory(withids=withids, urls=adpurls):
            yield adp
        async for disk in self._get_disk_inventory(withids=withids, urls=diskurls):
            yield disk

    async def _get_disk_inventory(self, onlyname=False, withids=False, urls=None):
        if not urls:
            urls = await self._get_disk_urls()
        async for inf in self._do_bulk_requests(urls):
            inf, _ = inf
            ddata = {
                'Model': inf.get('Model', None),
                'Serial Number': inf.get('SerialNumber', None),
                'Description': inf.get('Name'),
            }
            loc = inf.get('PhysicalLocation', {}).get('Info', None)
            if loc:
                dname = 'Disk {0}'.format(loc)
            else:
                dname = inf.get('Id', 'Disk')
            yield (dname, ddata)

    async def _get_adp_inventory(self, onlyname=False, withids=False, urls=None):
        foundmacs = False
        macinfobyadpname = {}
        if 'NetworkInterfaces' in self._varsysinfo:
            nifdata = await self._get_expanded_data(
                self._varsysinfo['NetworkInterfaces']['@odata.id'])
            for nifinfo in nifdata.get('Members', []):
                nadurl = nifinfo.get(
                    'Links', {}).get('NetworkAdapter', {}).get("@odata.id")
                if nadurl:
                    nadinfo = await self._do_web_request(nadurl)
                    if 'Name' not in nadinfo:
                        continue
                    nicname = nadinfo['Name']
                    if nicname == 'NetworkAdapter':
                        nicname = nadinfo.get('Model', nicname)                   
                    yieldinf = {}
                    macidx = 1
                    if 'Ports' in nadinfo:
                        for portinfo in (await self._get_expanded_data(
                                nadinfo['Ports']['@odata.id'])).get('Members', []):
                            ethinfo = portinfo.get('Ethernet', {})
                            if ethinfo:
                                macs = [x for x in ethinfo.get('AssociatedMACAddresses', [])]
                                for mac in macs:
                                    label = 'MAC Address {}'.format(macidx)
                                    yieldinf[label] = _normalize_mac(mac)
                                    macidx += 1
                                    foundmacs = True
                            ibinfo = portinfo.get('InfiniBand', {})
                            if ibinfo:
                                macs = [x for x in ibinfo.get('AssociatedPortGUIDs', [])]
                                for mac in macs:
                                    label = 'Port GUID {}'.format(macidx)
                                    yieldinf[label] = mac
                                    macidx += 1
                                    foundmacs = True                            
                        macinfobyadpname[nicname] = yieldinf
                    else:
                        for ctrlr in nadinfo.get('Controllers', []):
                            porturls = [x['@odata.id'] for x in ctrlr.get(
                                'Links', {}).get('Ports', [])]
                            for porturl in porturls:
                                portinfo = await self._do_web_request(porturl)
                                macs = [x for x in portinfo.get(
                                    'Ethernet', {}).get(
                                        'AssociatedMACAddresses', [])]
                                for mac in macs:
                                    label = 'MAC Address {}'.format(macidx)
                                    yieldinf[label] = _normalize_mac(mac)
                                    macidx += 1
                                    foundmacs = True
                        macinfobyadpname[nicname] = yieldinf
        if not urls:
            urls = await self._get_adp_urls()
        async for inf in self._do_bulk_requests(urls):
            adpinfo, url = inf
            aname = adpinfo.get('Name', 'Unknown')
            if aname in self._hwnamemap:
                aname = adpinfo.get('Id', aname)
            if aname in self._hwnamemap:
                self._hwnamemap[aname] = None
            else:
                self._hwnamemap[aname] = (url, self._get_adp_inventory)
            if onlyname:
                if withids:
                    yield aname, adpinfo.get('Id', aname)
                else:
                    yield aname
                continue
            functions = adpinfo.get('Links', {}).get('PCIeFunctions', [])
            nicidx = 1
            if withids:
                yieldinf = {'Id': adpinfo.get('Id', aname)}
            else:
                yieldinf = {}
            if aname in macinfobyadpname:
                yieldinf.update(macinfobyadpname[aname])
            funurls = [x['@odata.id'] for x in functions]
            async for fun in self._do_bulk_requests(funurls):
                funinfo, url = fun
                yieldinf['PCI Device ID'] = funinfo['DeviceId'].replace('0x',
                                                                        '')
                yieldinf['PCI Vendor ID'] = funinfo['VendorId'].replace('0x',
                                                                        '')
                yieldinf['PCI Subsystem Device ID'] = funinfo[
                    'SubsystemId'].replace('0x', '')
                yieldinf['PCI Subsystem Vendor ID'] = funinfo[
                    'SubsystemVendorId'].replace('0x', '')
                yieldinf['Type'] = funinfo['DeviceClass']
                if aname not in macinfobyadpname:
                    for nicinfo in funinfo.get('Links', {}).get(
                            'EthernetInterfaces', []):
                        nicinfo = await self._do_web_request(nicinfo['@odata.id'])
                        macaddr = nicinfo.get('MACAddress', None)
                        if macaddr:
                            macaddr = _normalize_mac(macaddr)
                            foundmacs = True
                            yieldinf['MAC Address {0}'.format(nicidx)] = macaddr
                            nicidx += 1
            if aname in macinfobyadpname:
                del macinfobyadpname[aname]
            yield aname, yieldinf
        if onlyname:
            return
        if macinfobyadpname:
            for adp in macinfobyadpname:
                yield adp, macinfobyadpname[adp]
        if not foundmacs:
            # No PCIe device inventory, but *maybe* ethernet inventory...
            idxsbyname = {}
            for nicinfo in self._get_eth_urls():
                nicinfo = await self._do_web_request(nicinfo)
                nicname = nicinfo.get('Name', None)
                nicinfo = nicinfo.get('MACAddress', nicinfo.get('PermanentAddress', None))
                if nicinfo and ':' not in nicinfo:
                    nicinfo = ':'.join((
                        nicinfo[:2], nicinfo[2:4], nicinfo[4:6], nicinfo[6:8],
                        nicinfo[8:10], nicinfo[10:12]))
                if not nicname:
                    nicname = 'NIC'
                if nicinfo:
                    if nicname not in idxsbyname:
                        idxsbyname[nicname] = 0
                    idxsbyname[nicname] += 1
                    nicinfo = nicinfo.lower()
                    yield (nicname,
                            {'MAC Address {}'.format(idxsbyname[nicname]): nicinfo})


    async def _get_eth_urls(self):
        ethurls = self._varsysinfo.get('EthernetInterfaces', {})
        ethurls = ethurls.get('@odata.id', None)
        if ethurls:
            ethurls = await self._do_web_request(ethurls)
            ethurls = ethurls.get('Members', [])
            urls = [x['@odata.id'] for x in ethurls]
        else:
            urls = []
        return urls

    async def _get_adp_urls(self):
        adpurls = self._varsysinfo.get('PCIeDevices', [])
        if adpurls:
            urls = [x['@odata.id'] for x in adpurls]
        else:
            urls = []
        return urls

    async def _get_cpu_inventory(self, onlynames=False, withids=False, urls=None):
        async for currcpuinfo in self._get_cpu_data():
            url = currcpuinfo['@odata.id']
            name = currcpuinfo.get('Name', 'CPU')
            if name in self._hwnamemap:
                self._hwnamemap[name] = None
            else:
                self._hwnamemap[name] = (url, self._get_cpu_inventory)
            if onlynames:
                yield name
                continue
            cpuinfo = {'Model': currcpuinfo.get('Model', None)}
            yield name, cpuinfo

    async def _get_disk_urls(self):
        storurl = self._varsysinfo.get('Storage', {}).get('@odata.id', None)
        urls = []
        if storurl:
            storurl = await self._do_web_request(storurl)
            for url in storurl.get('Members', []):
                url = url['@odata.id']
                ctldata = await self._do_web_request(url)
                for durl in ctldata.get('Drives', []):
                    urls.append(durl['@odata.id'])
        return urls

    def _get_cpu_urls(self):
        md = self._get_cpu_data(False)
        return [x['@odata.id'] for x in md]

    async def _get_cpu_data(self, expand='.'):
        for sysurl in self._allsysurls:
            currsysdata = await self._do_web_request(sysurl)
            currcpuurl = currsysdata.get('Processors', {}).get('@odata.id', None)
            if currcpuurl:
                currcpudata = await self._get_expanded_data(currcpuurl, expand)
                for memb in currcpudata.get('Members', []):
                    yield memb

    async def _get_mem_inventory(self, onlyname=False, withids=False, urls=None):
        memdata = await self._get_mem_data()
        for currmeminfo in memdata:
            url = currmeminfo['@odata.id']
            name = currmeminfo.get('Name', 'Memory')
            if name in self._hwnamemap:
                self._hwnamemap[name] = None
            else:
                self._hwnamemap[name] = (url, self._get_mem_inventory)
            if onlyname:
                yield name
                continue
            if currmeminfo.get(
                    'Status', {}).get('State', 'Absent') == 'Absent':
                yield (name, None)
                continue
            currspeed = currmeminfo.get('OperatingSpeedMhz', None)
            if currspeed:
                currspeed = int(currspeed)
                currspeed = currspeed * 8 - (currspeed * 8 % 100)
            meminfo = {
                'capacity_mb': currmeminfo.get('CapacityMiB', None),
                'manufacturer': currmeminfo.get('Manufacturer', None),
                'memory_type': currmeminfo.get('MemoryDeviceType', None),
                'model': currmeminfo.get('PartNumber', None),
                'module_type': currmeminfo.get('BaseModuleType', None),
                'serial': currmeminfo.get('SerialNumber', None),
                'speed': currspeed,
            }
            yield (name, meminfo)

    async def _get_mem_urls(self):
        md = await self._get_mem_data(False)
        return [x['@odata.id'] for x in md]

    async def _get_mem_data(self, expand='.'):
        memmembers = []
        for sysurl in self._allsysurls:
            currsysdata = await self._do_web_request(sysurl)
            currmemurl = currsysdata.get('Memory', {}).get('@odata.id', None)
            if currmemurl:
                currmemdata = await self._get_expanded_data(currmemurl, expand)
                memmembers.extend(currmemdata.get('Members', []))
        return memmembers        

    async def _get_expanded_data(self, url, expand='.'):
        topdata = []
        if not url:
            return topdata
        if not expand:
            return await self._do_web_request(url)
        elif await self.supports_expand(url):
            return await self._do_web_request(url + '?$expand=' + expand)
        else:  # emulate expand behavior
            topdata = await self._do_web_request(url)
            newmembers = []
            for x in topdata.get('Members', []):
                newmembers.append(await self._do_web_request(x['@odata.id']))
            topdata['Members'] = newmembers
            return topdata
        return topdata
 
    async def get_ikvm_methods(self):
        return []

    async def get_ikvm_launchdata(self):
        return {}

    def get_storage_configuration(self):
        raise exc.UnsupportedFunctionality(
            'Remote storage configuration not supported on this platform')

    def remove_storage_configuration(self, cfgspec):
        raise exc.UnsupportedFunctionality(
            'Remote storage configuration not supported on this platform')

    def apply_storage_configuration(self, cfgspec):
        raise exc.UnsupportedFunctionality(
            'Remote storage configuration not supported on this platform')

    def check_storage_configuration(self, cfgspec):
        raise exc.UnsupportedFunctionality(
            'Remote storage configuration not supported on this platform')

    def upload_media(self, filename, progress=None, data=None):
        raise exc.UnsupportedFunctionality(
            'Remote media upload not supported on this platform')

    async def get_update_status(self):
        upd = await self._do_web_request('/redfish/v1/UpdateService')
        health = upd.get('Status', {}).get('Health', 'Unknown')
        if health == 'OK':
            return 'ready'
        if health == 'Unknown' and upd.get('ServiceEnabled'):
            return 'ready'       
        return 'unavailable'

    def format_message(self, msg):
        try:
            return '{}: {}'.format(msg.get('MessageSeverity', msg['Severity']), msg['Message'])
        except Exception:
            return repr(msg)

    def format_messages(self, response):
        msgs = response.get('Messages', [])
        return ';'.join(self.format_message(x) for x in msgs)

    async def update_firmware(self, filename, data=None, progress=None, bank=None, otherfields=()):
        # disable cache to make sure we trigger the token renewal logic if needed
        usd, upurl, ismultipart = await self.retrieve_firmware_upload_url()
        try:
            uploadthread = await webclient.make_uploader(
                self.webclient, upurl, filename, data, formname='UpdateFile', formwrap=ismultipart,
                otherfields=otherfields)
            wc = self.webclient
            while not uploadthread.completed():
                try:
                    await uploadthread.join(3)
                except asyncio.TimeoutError:
                    pass
                if progress:
                    progress(
                        {'phase': 'upload',
                         'progress': 100 * await uploadthread.get_progress()})
            rspstatus, rsp, headers = uploadthread.get_response()
            if (rspstatus >= 300
                    or rspstatus < 200):
                errmsg = f'Update attempt resulted in response status {rspstatus}'
                try:
                    rsp = json.loads(rsp)
                    errmsg = (
                        rsp['error'][
                            '@Message.ExtendedInfo'][0]['Message'])
                except Exception:
                    errmsg = errmsg + ': ' + repr(rsp)
                    raise Exception(errmsg)
                raise Exception(errmsg)
            return await self.continue_update(rsp, progress)
        finally:
            if 'HttpPushUriTargetsBusy' in usd:
                await self._do_web_request(
                    '/redfish/v1/UpdateService',
                    {'HttpPushUriTargetsBusy': False}, method='PATCH')

    async def continue_update(self, rsp, progress):
            monitorurl = rsp['@odata.id']
            return await self.monitor_update_progress(monitorurl, progress)

    async def monitor_update_progress(self, monitorurl, progress):
            complete = False
            phase = "apply"
            statetype = 'TaskState'
            # sometimes we get an empty pgress when transitioning from the apply phase to
            # the validating phase; add a retry here so we don't exit the loop in this case
            retry = 3
            pct = 0.0
            while not complete and retry > 0:
                try:
                    pgress = await self._do_web_request(monitorurl, cache=False)
                except socket.timeout:
                    pgress = None
                if not pgress:
                    retry -= 1
                    await asyncio.sleep(3)
                    continue
                retry = 3
                for msg in pgress.get('Messages', []):
                    if 'Verify failed' in msg.get('Message', ''):
                        raise Exception(msg['Message'])
                state = pgress[statetype]
                if state in ('Cancelled', 'Exception', 'Interrupted',
                             'Suspended'):
                    raise Exception(
                        self.format_messages(pgress))
                if 'PercentComplete' in pgress:
                    pct = float(pgress['PercentComplete'])
                complete = state == 'Completed'
                progress({'phase': phase, 'progress': pct})
                if complete:
                    msgs = pgress.get('Messages', [])
                    if msgs and 'OperationTransitionedToJob' in msgs[0].get('MessageId', ''):
                        monitorurl = pgress['Messages'][0]['MessageArgs'][0]
                        phase = 'validating'
                        statetype = 'JobState'
                        complete = False
                        await asyncio.sleep(3)
                else:
                    await asyncio.sleep(3)
            if not retry:
                raise Exception('Failed to monitor update progress due to excessive timeouts')
            return 'pending'


    async def retrieve_firmware_upload_url(self):
        usd = await self._do_web_request('/redfish/v1/UpdateService', cache=False)
        upurl = usd.get('MultipartHttpPushUri', None)
        ismultipart = True
        if not upurl:
            ismultipart = False
            if usd.get('HttpPushUriTargetsBusy', False):
                raise exc.TemporaryError('Cannot run multtiple updates to '
                                            'same target concurrently')
            try:
                upurl = usd['HttpPushUri']
            except KeyError:
                raise exc.UnsupportedFunctionality('Redfish firmware update only supported for implementations with push update support')
            if 'HttpPushUriTargetsBusy' in usd:
                await self._do_web_request('/redfish/v1/UpdateService',
                    {'HttpPushUriTargetsBusy': True}, method='PATCH')
                    
        return usd,upurl,ismultipart


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

    async def _get_session_token(self, wc):
        username = self.username
        password = self.password
        if not isinstance(username, str):
            username = username.decode()
        if not isinstance(password, str):
            password = password.decode()
        # specification actually indicates we can skip straight to this url
        _, status, headers = await wc.grab_response_with_status('/redfish/v1/SessionService/Sessions',
                          {'UserName': username, 'Password': password})
        if status < 200 or status >= 300:
            return
        self.xauthtoken = headers.get('X-Auth-Token')
        if self.xauthtoken:
            if 'Authorization' in wc.stdheaders:
                del wc.stdheaders['Authorization']
            if 'Authorization' in self.webclient.stdheaders:
                del self.webclient.stdheaders['Authorization']
            wc.stdheaders['X-Auth-Token'] = self.xauthtoken
            self.webclient.stdheaders['X-Auth-Token'] = self.xauthtoken


    async def _do_web_request(self, url, payload=None, method=None, cache=True, etag=None):
        res = None
        if cache and payload is None and method is None:
            res = self._get_cache(url)
        if res:
            return res
        # If doing a method that may change remote url state, invalidate cache
        self._invalidate_url_cache(url)
        wc = self.webclient.dupe()
        if etag:
            wc.stdheaders['If-Match'] = etag
        res = await wc.grab_json_response_with_status(url, payload, method=method)
        if res[1] == 401 and 'X-Auth-Token' in self.webclient.stdheaders:
            wc.set_basic_credentials(self.username, self.password)
            await self._get_session_token(wc)
            if etag:
                wc.stdheaders['If-Match'] = etag
            res = await wc.grab_json_response_with_status(url, payload,
                                                    method=method)
        if res[1] < 200 or res[1] >= 300:
            try:
                info = json.loads(res[0])
                errmsg = [
                    x.get('Message', x['MessageId']) for x in info.get(
                        'error', {}).get('@Message.ExtendedInfo', {})]
                errmsg = ','.join(errmsg)
                raise exc.RedfishError(errmsg)
            except (ValueError, KeyError):
                raise exc.PyghmiException(str(url) + ":" + res[0])
        if payload is None and method is None:
            self._urlcache[url] = {
                'contents': res[0],
                'vintage': os.times()[4]
            }
        return res[0]

    async def get_diagnostic_data(self, savefile, progress=None, autosuffix=None):
        """Download diagnostic data about target to a file

        This should be a payload that the vendor's support team can use
        to do diagnostics.
        :param savefile: File object or filename to save to
        :param progress: Callback to be informed about progress
        :param autosuffix: Have the library automatically amend filename per
                           vendor support requirements.
        :return:
        """
        raise exc.UnsupportedFunctionality(
            'Retrieving diagnostic data is not implemented for this platform')

    async def _get_license_collection_url(self, fishclient):
        overview = await fishclient._do_web_request('/redfish/v1/')
        licsrv = overview.get('LicenseService', {}).get('@odata.id', None)
        if not licsrv:
            raise exc.UnsupportedFunctionality()
        lcs = await fishclient._do_web_request(licsrv)
        licenses = lcs.get('Licenses', {}).get('@odata.id',None)
        if not licenses:
            raise exc.UnsupportedFunctionality()
        return licenses

    def get_extended_bmc_configuration(self, fishclient, hideadvanced=True):
        raise exc.UnsupportedFunctionality()


    async def _get_licenses(self, fishclient):
        licenses = await self._get_license_collection_url(fishclient)
        collection = await fishclient._do_web_request(licenses)
        alllic = [x['@odata.id'] for x in collection.get('Members', [])]
        for license in alllic:
            licdet = await fishclient._do_web_request(license)
            state = licdet.get('Status', {}).get('State')
            if state != 'Enabled':
                continue
            yield licdet

    async def get_licenses(self, fishclient):
        async for licdet in self._get_licenses(fishclient):
            name = licdet['Name']
            yield {'name': name, 'state': 'Active'}

    async def delete_license(self, name, fishclient):
        async for licdet in self._get_licenses(fishclient):
            lname = licdet['Name']
            if name == lname:
                await fishclient._do_web_request(licdet['@odata.id'], method='DELETE')

    async def save_licenses(self, directory, fishclient):
        async for licdet in self._get_licenses(fishclient):
            dload = licdet.get('DownloadURI', None)
            if dload:
                filename = os.path.basename(dload)
                savefile = os.path.join(directory, filename)
                if os.path.exists(savefile):
                    raise exc.PyghmiException(
                        'File {} already exists'.format(savefile))
                dler = webclient.make_downloader(fishclient.wc, dload, savefile)
                await dler.join()
                yield savefile

    async def apply_license(self, filename, fishclient, progress=None, data=None):
        licenses = await self._get_license_collection_url(fishclient)
        if data is None:
            data = open(filename, 'rb')
        licdata = data.read()
        lic64 = base64.b64encode(licdata).decode()
        licinfo = {"LicenseString": lic64}
        await fishclient._do_web_request(licenses, licinfo)


    def get_user_expiration(self, uid):
        return None

    async def reseat_bay(self, bay):
        raise exc.UnsupportedFunctionality(
            'Reseat not supported on this platform')
