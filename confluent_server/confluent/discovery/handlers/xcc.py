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

import confluent.discovery.handlers.bmchandler as bmchandler
import pyghmi.exceptions as pygexc


class NodeHandler(bmchandler.NodeHandler):

    def preconfig(self):
        self.discoverable = True
        # attempt to enable SMM
        ipmicmd = None
        try:
            ipmicmd = self._get_ipmicmd()
            ipmicmd.xraw_command(netfn=0x3a, command=0xf1, data=(1,))
            self.discoverable = False
        except pygexc.IpmiException as e:
            if e.ipmicode != 193:
                # Do not try to discover an XCC that can't be preconfigged
                # can't tell 100% if it's safe to do
                self.discoverable = False
        if ipmicmd:
            ipmicmd.ipmi_session.logout()

    @property
    def discoverable_by_switch(self):
        return self.discoverable

