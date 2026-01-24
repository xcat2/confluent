# Copyright 2019 Lenovo
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

import confluent.discovery.handlers.bmc as bmchandler
import eventlet
import confluent.util as util
try:
    from urllib import urlencode
except ImportError:
    from urllib.parse import urlencode
import aiohmi.util.webclient as webclient


class NodeHandler(bmchandler.NodeHandler):
    DEFAULT_USER = 'admin'
    DEFAULT_PASS = 'admin'
    devname = 'BMC'
    maxmacs = 2

    def validate_cert(self, certificate):
        # broadly speaking, merely checks consistency moment to moment,
        # but if https_cert gets stricter, this check means something
        fprint = util.get_fingerprint(self.https_cert)
        return util.cert_matches(fprint, certificate)

    def get_webclient(self, user, passwd, newuser, newpass):
        wc = webclient.WebConnection(self.ipaddr, 443,
                                            verifycallback=self.validate_cert)
        wc.connect()
        authdata = urlencode({'username': user, 'password': passwd,
                              'weblogsign': 1})
        res = wc.grab_json_response_with_status('/api/session', authdata)
        if res[1] == 200:
            if res[0].get('force_password', 1) == 0:
                # Need to handle password change
                passchange = {
                    'Password': newpass,
                    'RetypePassword': newpass,
                    'param': 4,
                    'username': 'admin',
                    'privilege': 4,
                }
                passchange = urlencode(passchange)
                rsp = wc.grab_json_response_with_status('/api/reset-pass',
                                                        passchange)
                rsp = wc.grab_json_response_with_status('/api/session',
                                                        method='DELETE')

    def config(self, nodename, reset=False):
        self.nodename = nodename
        creds = self.configmanager.get_node_attributes(
            self.nodename, ['secret.hardwaremanagementuser',
                            'secret.hardwaremanagementpassword'],
            decrypt=True)
        user, passwd, isdefault = self.get_node_credentials(
                nodename, creds, 'admin', 'admin')
        if not isdefault:
            self.get_webclient(self.DEFAULT_USER, self.DEFAULT_PASS, user,
                               passwd)
        self._bmcconfig(nodename, False)
