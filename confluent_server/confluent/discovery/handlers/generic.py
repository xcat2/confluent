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

import confluent.util as util
import errno
import socket
import aiohmi.util.webclient as webclient

class NodeHandler(object):
    https_supported = True
    is_enclosure = False
    devname = ''
    maxmacs = 3  # reasonable default, allowing for common scenario of
                 # shared nic in theory, but blocking enclosure managers
                 # and uplink ports

    def __init__(self, info, configmanager):
        self._certfailreason = None
        self._fp = None
        self.info = info
        self.configmanager = configmanager
        targsa = [None]
        self._ipaddr = None
        self.relay_url = None
        self.relay_server = None
        self.web_ip = None
        self.web_port = None
        self.https_cert = None
        # if this is a remote registered component, prefer to use the agent forwarder
        if info.get('forwarder_url', False):
            self.relay_url = info['forwarder_url']
            self.relay_server = info['forwarder_server']
            return
        # first let us prefer LLA if possible, since that's most stable
        for sa in info['addresses']:
            if sa[0].startswith('fe80'):
                targsa = sa
                break
        else:
            if info.get('addresses', False):
                targsa = info['addresses'][0]
        self._ipaddr = socket.getnameinfo(
            targsa, socket.NI_NUMERICHOST|socket.NI_NUMERICSERV)[0]

    @classmethod
    def adequate(cls, info):
        # Check if the referenced info is really enough, if false, a rescan
        # may occur against the target in a short while
        return True

    def scan(self):
        # Do completely passive things to enhance data.
        # Probe is permitted to for example attempt a login
        # scan *only* does what it can without a login attempt
        return

    def probe(self):
        # Use appropriate direct strategy to gather data such as
        # serial number and uuid to flesh out data as needed
        return

    def preconfig(self, possiblenode):
        return

    def discoverable_by_switch(self, macs):
        # Given the number of macs sharing the port, is this handler
        # appropriate?
        return macs <= self.maxmacs

    def _savecert(self, certificate):
        self._fp = certificate
        return True

    def get_node_credentials(self, nodename, creds, defuser, defpass):
        user = creds.get(nodename, {}).get(
            'secret.hardwaremanagementuser', {}).get('value', None)
        havecustomcreds = False
        if user and not isinstance(user, str):
            user = user.decode('utf8')
        if user is not None and user != defuser:
            havecustomcreds = True
        else:
            user = defuser
        passwd = creds.get(nodename, {}).get(
            'secret.hardwaremanagementpassword', {}).get('value', None)
        if passwd and not isinstance(passwd, str):
            passwd = passwd.decode('utf8')
        if passwd is not None and passwd != defpass:
            havecustomcreds = True
        else:
            passwd = defpass
        return user, passwd, not havecustomcreds


    @property
    def ipaddr(self):
        return self._ipaddr

    @property
    def cert_fail_reason(self):
        if self._certfailreason == 1:
            return 'refused'
        elif self._certfailreason == 2:
            return 'unreachable'

    async def get_https_cert(self):
        if self._fp:
            return self._fp
        ip, port = await self.get_web_port_and_ip()
        wc = webclient.WebConnection(ip, verifycallback=self._savecert, port=port)
        try:
            await wc.request('GET', '/')
        except IOError as ie:
            if ie.errno == errno.ECONNREFUSED:
                self._certfailreason = 1
                return None
            elif ie.errno == errno.EHOSTUNREACH:
                self._certfailreason = 2
                return None
            self._certfailreason = 2
            return None
        except Exception:
            self._certfailreason = 2
            return None
        self.https_cert = self._fp
        return self._fp

    async def get_web_port_and_ip(self):
        if self.web_ip:
            return self.web_ip, self.web_port
        # get target ip and port, either direct or relay as applicable
        if self.relay_url:
            kv = util.TLSCertVerifier(self.configmanager, self.relay_server,
                                  'pubkeys.tls_hardwaremanager').verify_cert
            w = webclient.WebConnection(self.relay_server, verifycallback=kv)
            relaycreds = self.configmanager.get_node_attributes(self.relay_server, 'secret.*', decrypt=True)
            relaycreds = relaycreds.get(self.relay_server, {})
            relayuser = relaycreds.get('secret.hardwaremanagementuser', {}).get('value', None)
            relaypass = relaycreds.get('secret.hardwaremanagementpassword', {}).get('value', None)
            if not relayuser or not relaypass:
                raise Exception('No credentials for {0}'.format(self.relay_server))
            w.set_basic_credentials(relayuser, relaypass)
            await w.request('GET', self.relay_url)
            r = w.getresponse()
            rb = r.read()
            if r.code != 302:
                raise Exception('Unexpected return from forwarder')
            newurl = r.getheader('Location')
            self.web_port = int(newurl.rsplit(':', 1)[-1][:-1])
            self.web_ip = self.relay_server
        else:
            self.web_port = 443
            self.web_ip = self.ipaddr
        return self.web_ip, self.web_port
