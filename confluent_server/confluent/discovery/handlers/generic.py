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

import errno
import eventlet
webclient = eventlet.import_patched('pyghmi.util.webclient')

class NodeHandler(object):
    https_supported = True
    is_enclosure = False
    devname = ''
    maxmacs = 2  # reasonable default, allowing for common scenario of
                 # shared nic in theory, but blocking enclosure managers
                 # and uplink ports

    def __init__(self, info, configmanager):
        self._certfailreason = None
        self._fp = None
        self.info = info
        self.configmanager = configmanager
        targsa = [None]
        # first let us prefer LLA if possible, since that's most stable
        for sa in info['addresses']:
            if sa[0].startswith('fe80'):
                targsa = sa
                break
        else:
            if info.get('addresses', False):
                targsa = info['addresses'][0]
        self.ipaddr = targsa[0]

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

    def preconfig(self):
        return

    def discoverable_by_switch(self, macs):
        # Given the number of macs sharing the port, is this handler
        # appropriate?
        return macs <= self.maxmacs

    def _savecert(self, certificate):
        self._fp = certificate
        return True

    @property
    def cert_fail_reason(self):
        if self._certfailreason == 1:
            return 'refused'
        elif self._certfailreason == 2:
            return 'unreachable'

    @property
    def https_cert(self):
        if self._fp:
            return self._fp
        if ':' in self.ipaddr:
            ip = '[{0}]'.format(self.ipaddr)
        else:
            ip = self.ipaddr
        wc = webclient.SecureHTTPConnection(ip, verifycallback=self._savecert)
        try:
            wc.connect()
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
        return self._fp