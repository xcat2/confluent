# Copyright 2024 Lenovo
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

import confluent.discovery.handlers.generic as generic
import confluent.exceptions as exc
import confluent.netutil as netutil
import confluent.util as util
import eventlet
import eventlet.support.greendns
import json
try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode

getaddrinfo = eventlet.support.greendns.getaddrinfo

webclient = eventlet.import_patched('pyghmi.util.webclient')

def get_host_interface_urls(wc, mginfo):
    returls = []
    hifurl = mginfo.get('HostInterfaces', {}).get('@odata.id', None)
    if not hifurl:
        return None
    hifinfo = wc.grab_json_response(hifurl)
    hifurls = hifinfo.get('Members', [])
    for hifurl in hifurls:
        hifurl = hifurl['@odata.id']
        hifinfo = wc.grab_json_response(hifurl)
        acturl = hifinfo.get('ManagerEthernetInterface', {}).get('@odata.id', None)
        if acturl:
            returls.append(acturl)
    return returls


class NodeHandler(generic.NodeHandler):
    devname = 'BMC'

    def __init__(self, info, configmanager):
        self.trieddefault = None
        self.targuser = None
        self.curruser = None
        self.currpass = None
        self.targpass = None
        self.nodename = None
        self.csrftok = None
        self.channel = None
        self.atdefault = True
        self._srvroot = None
        self._mgrinfo = None
        super(NodeHandler, self).__init__(info, configmanager)

    def srvroot(self, wc):
        if not self._srvroot:
            srvroot, status = wc.grab_json_response_with_status('/redfish/v1/')
            if status == 200:
                self._srvroot = srvroot
        return self._srvroot

    def mgrinfo(self, wc):
        if not self._mgrinfo:
            mgrs = self.srvroot(wc)['Managers']['@odata.id']
            rsp = wc.grab_json_response(mgrs)
            if len(rsp['Members']) != 1:
                raise Exception("Can not handle multiple Managers")
            mgrurl = rsp['Members'][0]['@odata.id']
            self._mgrinfo = wc.grab_json_response(mgrurl)
        return self._mgrinfo


    def get_firmware_default_account_info(self):
        raise Exception('This must be subclassed')

    def scan(self):
        c = webclient.SecureHTTPConnection(self.ipaddr, 443, verifycallback=self.validate_cert)
        i = c.grab_json_response('/redfish/v1/')
        uuid = i.get('UUID', None)
        if uuid:
            self.info['uuid'] = uuid.lower()

    def validate_cert(self, certificate):
        # broadly speaking, merely checks consistency moment to moment,
        # but if https_cert gets stricter, this check means something
        fprint = util.get_fingerprint(self.https_cert)
        return util.cert_matches(fprint, certificate)

    def enable_ipmi(self, wc):
        npu = self.mgrinfo(wc).get(
            'NetworkProtocol', {}).get('@odata.id', None)
        if not npu:
            raise Exception('Cannot enable IPMI, no NetworkProtocol on BMC')
        npi = wc.grab_json_response(npu)
        if not npi.get('IPMI', {}).get('ProtocolEnabled'):
            wc.set_header('If-Match', '*')
            wc.grab_json_response_with_status(
                npu, {'IPMI': {'ProtocolEnabled': True}}, method='PATCH')
        acctinfo = wc.grab_json_response_with_status(
            self.target_account_url(wc))
        acctinfo = acctinfo[0]
        actypes = acctinfo['AccountTypes']
        candidates = acctinfo['AccountTypes@Redfish.AllowableValues']
        if 'IPMI' not in actypes and 'IPMI' in candidates:
            actypes.append('IPMI')
            acctupd = {
                'AccountTypes': actypes,
                'Password': self.currpass,
                }
            rsp = wc.grab_json_response_with_status(
                self.target_account_url(wc), acctupd, method='PATCH')

    def _get_wc(self):
        defuser, defpass = self.get_firmware_default_account_info()
        wc = webclient.SecureHTTPConnection(self.ipaddr, 443, verifycallback=self.validate_cert)
        wc.set_basic_credentials(defuser, defpass)
        wc.set_header('Content-Type', 'application/json')
        wc.set_header('Accept', 'application/json')
        authmode = 0
        if not self.trieddefault:
            rsp, status = wc.grab_json_response_with_status('/redfish/v1/Managers')
            if status == 403:
                self.trieddefault = True
                chgurl = None
                rsp = json.loads(rsp)
                currerr = rsp.get('error', {})
                ecode = currerr.get('code', None)
                if ecode.endswith('PasswordChangeRequired'):
                    for einfo in currerr.get('@Message.ExtendedInfo', []):
                        if einfo.get('MessageId', None).endswith('PasswordChangeRequired'):
                            for msgarg in einfo.get('MessageArgs'):
                                chgurl = msgarg
                                break
                if chgurl:
                    if self.targpass == defpass:
                        raise Exception("Must specify a non-default password to onboard this BMC")
                    wc.set_header('If-Match', '*')
                    cpr = wc.grab_json_response_with_status(chgurl, {'Password': self.targpass}, method='PATCH')
                    if cpr[1] >= 200 and cpr[1] < 300:
                        self.curruser = defuser
                        self.currpass = self.targpass
                        wc.set_basic_credentials(self.curruser, self.currpass)
                        _, status = wc.grab_json_response_with_status('/redfish/v1/Managers')
                        tries = 10
                        while status >= 300 and tries:
                            eventlet.sleep(1)
                            _, status = wc.grab_json_response_with_status('/redfish/v1/Managers')
                    return wc

            if status > 400:
                self.trieddefault = True
                if status == 401:
                    wc.set_basic_credentials(defuser, self.targpass)
                    rsp, status = wc.grab_json_response_with_status('/redfish/v1/Managers')
                    if status == 200:  # Default user still, but targpass
                        self.currpass = self.targpass
                        self.curruser = defuser
                        return wc
                    elif self.targuser != defuser:
                        wc.set_basic_credentials(self.targuser, self.targpass)
                        rsp, status = wc.grab_json_response_with_status('/redfish/v1/Managers')
                    if status != 200:
                        raise Exception("Target BMC does not recognize firmware default credentials nor the confluent stored credential")
            else:
                self.curruser = defuser
                self.currpass = defpass
                return wc
        if self.curruser:
            wc.set_basic_credentials(self.curruser, self.currpass)
            rsp, status = wc.grab_json_response_with_status('/redfish/v1/Managers')
            if status != 200:
                return None
            return wc
        wc.set_basic_credentials(self.targuser, self.targpass)
        rsp, status = wc.grab_json_response_with_status('/redfish/v1/Managers')
        if status != 200:
            return None
        self.curruser = self.targuser
        self.currpass = self.targpass
        return wc

    def target_account_url(self, wc):
        asrv = self.srvroot(wc).get('AccountService', {}).get('@odata.id')
        rsp, status = wc.grab_json_response_with_status(asrv)
        accts = rsp.get('Accounts', {}).get('@odata.id')
        rsp, status = wc.grab_json_response_with_status(accts)
        accts = rsp.get('Members', [])
        for accturl in accts:
            accturl = accturl.get('@odata.id', '')
            if accturl:
                rsp, status = wc.grab_json_response_with_status(accturl)
                if rsp.get('UserName', None) == self.curruser:
                    targaccturl = accturl
                    break
        else:
            raise Exception("Unable to identify Account URL to modify on this BMC")
        return targaccturl

    def config(self, nodename):
        mgrs = None
        self.nodename = nodename
        creds = self.configmanager.get_node_attributes(
            nodename, ['secret.hardwaremanagementuser',
                       'secret.hardwaremanagementpassword',
                       'hardwaremanagement.manager',
                       'hardwaremanagement.method',
                       'console.method'],
            True)
        cd = creds.get(nodename, {})
        defuser, defpass = self.get_firmware_default_account_info()
        user, passwd, _ = self.get_node_credentials(
                nodename, creds, defuser, defpass)
        user = util.stringify(user)
        passwd = util.stringify(passwd)
        self.targuser = user
        self.targpass = passwd
        wc = self._get_wc()
        curruserinfo = {}
        authupdate = {}
        wc.set_header('Content-Type', 'application/json')
        if user != self.curruser:
            authupdate['UserName'] = user
        if passwd != self.currpass:
            authupdate['Password'] = passwd
        if authupdate:
            targaccturl = self.target_account_url(wc)
            rsp, status = wc.grab_json_response_with_status(targaccturl, authupdate, method='PATCH')
            if status >= 300:
                raise Exception("Failed attempting to update credentials on BMC")
            self.curruser = user
            self.currpass = passwd
            wc.set_basic_credentials(user, passwd)
            _, status = wc.grab_json_response_with_status('/redfish/v1/Managers')
            tries = 10
            while tries and status >= 300:
                tries -= 1
                eventlet.sleep(1.0)
                _, status = wc.grab_json_response_with_status(
                    '/redfish/v1/Managers')
        if (cd.get('hardwaremanagement.method', {}).get('value', 'ipmi') != 'redfish'
                or cd.get('console.method', {}).get('value', None) == 'ipmi'):
            self.enable_ipmi(wc)
        if ('hardwaremanagement.manager' in cd and
                cd['hardwaremanagement.manager']['value'] and
                not cd['hardwaremanagement.manager']['value'].startswith(
                    'fe80::')):
            newip = cd['hardwaremanagement.manager']['value']
            newip = newip.split('/', 1)[0]
            newipinfo = getaddrinfo(newip, 0)[0]
            newip = newipinfo[-1][0]
            if ':' in newip:
                raise exc.NotImplementedException('IPv6 remote config TODO')
            hifurls = get_host_interface_urls(wc, self.mgrinfo(wc))
            mgtnicinfo = self.mgrinfo(wc)['EthernetInterfaces']['@odata.id']
            mgtnicinfo = wc.grab_json_response(mgtnicinfo)
            mgtnics = [x['@odata.id'] for x in mgtnicinfo.get('Members', [])]
            actualnics = []
            for candnic in mgtnics:
                if candnic in hifurls:
                    continue
                actualnics.append(candnic)
            if len(actualnics) != 1:
                raise Exception("Multi-interface BMCs are not supported currently")
            currnet = wc.grab_json_response(actualnics[0])
            netconfig = netutil.get_nic_config(self.configmanager, nodename, ip=newip)
            newconfig = {
                "Address": newip,
                "SubnetMask": netutil.cidr_to_mask(netconfig['prefix']),
                }
            newgw = netconfig['ipv4_gateway']
            if newgw:
                newconfig['Gateway'] = newgw
            else:
                newconfig['Gateway'] = newip  # required property, set to self just to have a value
            for net in currnet.get("IPv4Addresses", []):
                if net["Address"] == newip and net["SubnetMask"] == newconfig['SubnetMask'] and (not newgw or newconfig['Gateway'] == newgw):
                    break
            else:
                wc.set_header('If-Match', '*')
                rsp, status = wc.grab_json_response_with_status(actualnics[0], {
                    'DHCPv4': {'DHCPEnabled': False},
                    'IPv4StaticAddresses': [newconfig]}, method='PATCH')
        elif self.ipaddr.startswith('fe80::'):
            self.configmanager.set_node_attributes(
                {nodename: {'hardwaremanagement.manager': self.ipaddr}})
        else:
            raise exc.TargetEndpointUnreachable(
                'hardwaremanagement.manager must be set to desired address (No IPv6 Link Local detected)')


def remote_nodecfg(nodename, cfm):
    cfg = cfm.get_node_attributes(
            nodename, 'hardwaremanagement.manager')
    ipaddr = cfg.get(nodename, {}).get('hardwaremanagement.manager', {}).get(
        'value', None)
    ipaddr = ipaddr.split('/', 1)[0]
    ipaddr = getaddrinfo(ipaddr, 0)[0][-1]
    if not ipaddr:
        raise Exception('Cannot remote configure a system without known '
                         'address')
    info = {'addresses': [ipaddr]}
    nh = NodeHandler(info, cfm)
    nh.config(nodename)

if __name__ == '__main__':
    import confluent.config.configmanager as cfm
    c = cfm.ConfigManager(None)
    import sys
    info = {'addresses': [[sys.argv[1]]] }
    print(repr(info))
    testr = NodeHandler(info, c)
    testr.config(sys.argv[2])
