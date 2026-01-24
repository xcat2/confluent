# Copyright 2017 Lenovo
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

import codecs
import confluent.discovery.handlers.bmc as bmchandler
import confluent.exceptions as exc
import eventlet

import aiohmi.util.webclient as webclient

import struct
try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode
import eventlet.support.greendns
import confluent.netutil as netutil
import confluent.util as util
getaddrinfo = eventlet.support.greendns.getaddrinfo

from xml.etree.ElementTree import fromstring as rfromstring

def fromstring(inputdata):
    if isinstance(inputdata, bytes):
        cmpstr = b'!entity'
    else:
        cmpstr = '!entity'
    if cmpstr in inputdata.lower():
        raise Exception('!ENTITY not supported in this interface')
    # The measures above should filter out the risky facets of xml
    # We don't need sophisticated feature support
    return rfromstring(inputdata)  # nosec

def fixuuid(baduuid):
    # SMM dumps it out in hex
    uuidprefix = (baduuid[:8], baduuid[8:12], baduuid[12:16])
    a = codecs.encode(struct.pack('<IHH', *[int(x, 16) for x in uuidprefix]),
        'hex')
    a = util.stringify(a)
    uuid = (a[:8], a[8:12], a[12:16], baduuid[16:20], baduuid[20:])
    return '-'.join(uuid).lower()

class NodeHandler(bmchandler.NodeHandler):
    is_enclosure = True
    devname = 'SMM'
    maxmacs = 14  # support an enclosure, but try to avoid catching daisy chain

    def scan(self):
        # the UUID is in a weird order, fix it up to match
        # ipmi return and property value
        uuid = self.info.get('attributes', {}).get('uuid', None)
        if uuid:
            uuid = fixuuid(uuid[0])
            self.info['uuid'] = uuid

    def _validate_cert(self, certificate):
        # Assumption is by the time we call config, that discovery core has
        # vetted self._fp.  Our job here then is just to make sure that
        # the currect connection matches the previously saved cert
        if not self._fp:  # circumstances are that we haven't validated yet
            self._fp = certificate
        return certificate == self._fp

    def _webconfigrules(self, wc):
        rules = []
        for rule in self.ruleset.split(','):
            if '=' not in rule:
                continue
            name, value = rule.split('=')
            if value.lower() in ('no', 'none', 'disable', 'disabled'):
                value = '0'
            if name.lower() in ('expiry', 'expiration'):
                rules.append('passwordDurationDays:' + value)
                warndays = '5' if int(value) > 5 else value
                rules.append('passwordExpireWarningDays:' + warndays)
            if name.lower() in ('lockout', 'loginfailures'):
                rules.append('passwordFailAllowdNum:' + value)
            if name.lower() == 'reuse':
                rules.append('passwordReuseCheckNum:' + value)
        if rules:
            apirequest = 'set={0}'.format(','.join(rules))
            wc.request('POST', '/data', apirequest)
            wc.getresponse().read()

    def _webconfignet(self, wc, nodename):
        cfg = self.configmanager
        if 'service:lenovo-smm2' in self.info.get('services', []):
            # need to enable ipmi for now..
            wc.request('POST', '/data', 'set=DoCmd(0x06,0x40,0x01,0x82,0x84)')
            rsp = wc.getresponse()
            rsp.read()
            wc.request('POST', '/data', 'set=DoCmd(0x06,0x40,0x01,0x42,0x44)')
            rsp = wc.getresponse()
            rsp.read()
        cd = cfg.get_node_attributes(
            nodename, ['hardwaremanagement.manager'])
        smmip = cd.get(nodename, {}).get('hardwaremanagement.manager', {}).get('value', None)
        if smmip:
            smmip = smmip.split('/', 1)[0]
        if smmip and ':' not in smmip:
            smmip = getaddrinfo(smmip, 0)[0]
            smmip = smmip[-1][0]
            if smmip and ':' in smmip:
                raise exc.NotImplementedException('IPv6 not supported')
            wc.request('POST', '/data', 'get=hostname')
            rsp = wc.getresponse()
            rspdata = fromstring(util.stringify(rsp.read()))
            currip = rspdata.find('netConfig').find('ifConfigEntries').find(
                'ifConfig').find('v4IPAddr').text
            if currip == smmip:
                return
            netconfig = netutil.get_nic_config(cfg, nodename, ip=smmip)
            netmask = netutil.cidr_to_mask(netconfig['prefix'])
            setdata = 'set=ifIndex:0,v4DHCPEnabled:0,v4IPAddr:{0},v4NetMask:{1}'.format(smmip, netmask)
            gateway = netconfig.get('ipv4_gateway', None)
            if gateway:
                setdata += ',v4Gateway:{0}'.format(gateway)
            wc.request('POST', '/data', setdata)
            rsp = wc.getresponse()
            rspdata = util.stringify(rsp.read())
            if '<statusCode>0' not in rspdata:
                raise Exception("Error configuring SMM Network")
            return
        if smmip and ':' in smmip and not smmip.startswith('fe80::'):
            raise exc.NotImplementedException('IPv6 configuration TODO')
        if self.ipaddr.startswith('fe80::'):
            cfg.set_node_attributes(
                    {nodename: {'hardwaremanagement.manager': self.ipaddr}})

    def _webconfigcreds(self, username, password):
        ip, port = self.get_web_port_and_ip()
        wc = webclient.WebConnection(ip, port, verifycallback=self._validate_cert)
        wc.connect()
        authdata = {  # start by trying factory defaults
            'user': 'USERID',
            'password': 'PASSW0RD',
        }
        headers = {'Connection': 'keep-alive', 'Content-Type': 'application/x-www-form-urlencoded'}
        wc.request('POST', '/data/login', urlencode(authdata), headers)
        rsp = wc.getresponse()
        rspdata = util.stringify(rsp.read())
        if 'authResult>0' not in rspdata:
            # default credentials are refused, try with the actual
            authdata['user'] = username
            authdata['password'] = password
            wc.request('POST', '/data/login', urlencode(authdata), headers)
            rsp = wc.getresponse()
            rspdata = util.stringify(rsp.read())
            if 'renew_account' in rspdata:
                tmppassword = 'Tmp42' + password[5:]
                tokens = fromstring(rspdata)
                st2 = tokens.findall('st2')[0].text
                wc.set_header('ST2', st2)
                wc.request('POST', '/data/changepwd', 'oripwd={0}&newpwd={1}'.format(password, tmppassword))
                rsp = wc.getresponse()
                rspdata = rsp.read().decode('utf8')
                bdata = 'user={0}&password={1}'.format(username, tmppassword)
                wc.request('POST', '/data/login', bdata, headers)
                rsp = wc.getresponse()
                rspdata = rsp.read().decode('utf8')
                tokens = fromstring(rspdata)
                st2 = tokens.findall('st2')[0].text
                wc.set_header('ST2', st2)
                rules = 'set=passwordChangeInterval:0,passwordReuseCheckNum:0'
                wc.request('POST', '/data', rules)
                wc.getresponse().read()
                wc.request('POST', '/data/changepwd', 'oripwd={0}&newpwd={1}'.format(tmppassword, password))
                wc.getresponse().read()
                wc.request('POST', '/data/login', urlencode(authdata), headers)
                rsp = wc.getresponse()
                rspdata = util.stringify(rsp.read())
            if 'authResult>0' not in rspdata:
                raise Exception('Unknown username/password on SMM')
            tokens = fromstring(rspdata)
            st2 = tokens.findall('st2')[0].text
            wc.set_header('ST2', st2)
            return wc
        if 'renew_account' in rspdata:
            passwdchange = {'oripwd': 'PASSW0RD', 'newpwd': password}
            tokens = fromstring(rspdata)
            st2 = tokens.findall('st2')[0].text
            wc.set_header('ST2', st2)
            wc.request('POST', '/data/changepwd', urlencode(passwdchange))
            rsp = wc.getresponse()
            rspdata = rsp.read()
            authdata['password'] = password
            wc.request('POST', '/data/login', urlencode(authdata), headers)
            rsp = wc.getresponse()
            rspdata = util.stringify(rsp.read())
        if 'authResult>0' in rspdata:
            tokens = fromstring(rspdata)
            st2 = tokens.findall('st2')[0].text
            wc.set_header('ST2', st2)
            if username == 'USERID':
                return wc
            wc.request('POST', '/data', 'set=user(2,1,{0},511,,4,15,0)'.format(username))
            rsp = wc.getresponse()
            rspdata = rsp.read()
            wc.request('POST', '/data/logout')
            rsp = wc.getresponse()
            rspdata = rsp.read()
            authdata['user'] = username
            wc.request('POST', '/data/login', urlencode(authdata, headers))
            rsp = wc.getresponse()
            rspdata = rsp.read()
            tokens = fromstring(rspdata)
            st2 = tokens.findall('st2')[0].text
            wc.set_header('ST2', st2)
            return wc

    def config(self, nodename):
        # SMM for now has to reset to assure configuration applies
        cd = self.configmanager.get_node_attributes(
            nodename, ['secret.hardwaremanagementuser',
                       'secret.hardwaremanagementpassword',
                       'hardwaremanagement.manager', 'hardwaremanagement.method', 'console.method'],
                       True)
        cd = cd.get(nodename, {})
        targbmc = cd.get('hardwaremanagement.manager', {}).get('value', '')
        currip = self.ipaddr if self.ipaddr else ''
        if not currip.startswith('fe80::') and (targbmc.startswith('fe80::') or not targbmc):
            raise exc.TargetEndpointUnreachable(
                'hardwaremanagement.manager must be set to desired address (No IPv6 Link Local detected)')
        dpp = self.configmanager.get_node_attributes(
            nodename, 'discovery.passwordrules')
        self.ruleset = dpp.get(nodename, {}).get(
            'discovery.passwordrules', {}).get('value', '')
        creds = self.configmanager.get_node_attributes(
            nodename,
            ['secret.hardwaremanagementuser',
             'secret.hardwaremanagementpassword'], decrypt=True)
        username = creds.get(nodename, {}).get(
            'secret.hardwaremanagementuser', {}).get('value', 'USERID')
        passwd = creds.get(nodename, {}).get(
            'secret.hardwaremanagementpassword', {}).get('value', 'PASSW0RD')
        if not isinstance(username, str):
            username = username.decode('utf8')
        if not isinstance(passwd, str):
            passwd = passwd.decode('utf8')
        if passwd == 'PASSW0RD' and self.ruleset:
            raise Exception('Cannot support default password and setting password rules at same time')
        if passwd == 'PASSW0RD':
            # We must avoid hitting the web interface due to forced password change, best effert
            raise Exception('Using the default password is no longer supported')
        else:
            # Switch to full web based configuration, to mitigate risks with the SMM
            wc = self._webconfigcreds(username, passwd)
            self._webconfigrules(wc)
            self._webconfignet(wc, nodename)


# notes for smm:
# POST to:
# https://172.30.254.160/data/changepwd
# oripwd=PASSW0RD&newpwd=Passw0rd!4321
# got response:
# <?xml version="1.0" encoding="UTF-8"?><root><statusCode>0-ChangePwd</statusCode><fowardUrl>login.html</fowardUrl><status>ok</status></root>
# requires relogin
# https://172.30.254.160/index.html
# post to:
# https://172.30.254.160/data/login
# with body user=USERID&password=Passw0rd!4321
# yields:
# <?xml version="1.0" encoding="UTF-8"?><root> <status>ok</status> <authResult>0</authResult> <forwardUrl>index.html</forwardUrl> </root>
# note forwardUrl, if password change needed, will indicate something else
