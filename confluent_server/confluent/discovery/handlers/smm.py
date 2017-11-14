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

import confluent.discovery.handlers.bmc as bmchandler
import struct

def fixuuid(baduuid):
    # SMM dumps it out in hex
    uuidprefix = (baduuid[:8], baduuid[8:12], baduuid[12:16])
    a = struct.pack('<IHH', *[int(x, 16) for x in uuidprefix]).encode(
        'hex')
    uuid = (a[:8], a[8:12], a[12:16], baduuid[16:20], baduuid[20:])
    return '-'.join(uuid).lower()

class NodeHandler(bmchandler.NodeHandler):
    is_enclosure = True
    devname = 'SMM'
    maxmacs = 5  # support an enclosure, but try to avoid catching daisy chain

    def scan(self):
        # the UUID is in a weird order, fix it up to match
        # ipmi return and property value
        uuid = self.info.get('attributes', {}).get('uuid', None)
        if uuid:
            uuid = fixuuid(uuid[0])
            self.info['uuid'] = uuid

    def config(self, nodename):
        # SMM for now has to reset to assure configuration applies
        super(NodeHandler, self).config(nodename)

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