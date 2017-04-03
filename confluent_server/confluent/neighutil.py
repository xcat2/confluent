# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2016 Lenovo
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

# A consolidated manage of neighbor table information management.
# Ultimately, this should use AF_NETLINK, but in the interest of time,
# use ip neigh for the moment

import eventlet.green.subprocess as subprocess
import os

neightable = {}
neightime = 0

import re

_validmac = re.compile('..:..:..:..:..:..')


def update_neigh():
    global neightable
    global neightime
    neightable = {}
    if os.name == 'nt':
        return
    ipn = subprocess.Popen(['ip', 'neigh'], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
    (neighdata, err) = ipn.communicate()
    for entry in neighdata.split('\n'):
        entry = entry.split(' ')
        if len(entry) < 5 or not entry[4]:
            continue
        if entry[0] in ('192.168.0.100', '192.168.70.100', '192.168.70.125'):
            # Note that these addresses are common static ip addresses
            # that are hopelessly ambiguous if there are many
            # so ignore such entries and move on
            # ideally the system network steers clear of this landmine of
            # a subnet, but just in case
            continue
        if not _validmac.match(entry[4]):
            continue
        neightable[entry[0]] = entry[4]
    neightime = os.times()[4]


def refresh_neigh():
    global neightime
    if os.name == 'nt':
        return
    if os.times()[4] > (neightime + 30):
        update_neigh()
