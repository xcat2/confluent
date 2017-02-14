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

import eventlet
import eventlet.green.threading
import eventlet.support.greendns

ipmicommand = eventlet.import_patched('pyghmi.ipmi.command')
ipmicommand.session.select = eventlet.green.select
ipmicommand.session.threading = eventlet.green.threading
ipmicommand.session.socket.getaddrinfo = eventlet.support.greendns.getaddrinfo

DEFAULT_USER = 'USERID'
DEFAULT_PASS = 'PASSW0RD'

def interrogate(info):
    # get the uuid
    targsa = None
    # first let us prefer LLA if possible, since that's most stable
    for sa in info['addresses']:
        if sa[0].startswith('fe80'):
            targsa = sa
            break
    else:
        targsa = info['addresses'][0]
    ipaddr = targsa[0]
    icmd = pyghmi.ipmi.command.Command(ipaddr, DEFAULT_USER, DEFAULT_PASS)
    # get the uuid

def preconfig(info):
    # if stark, enable smm
    pass

