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
import pyghmi.exceptions as pygexc
import pyghmi.ipmi.private.util as pygutil


class NodeHandler(bmchandler.NodeHandler):
    devname = 'IMM'

    def probe(self):
        try:
            ipmicmd = self._get_ipmicmd()
            guiddata = ipmicmd.xraw_command(netfn=6, command=8)
            self.info['uuid'] = pygutil.decode_wireformat_uuid(
                guiddata['data'])
            ipmicmd.oem_init()
            bayid = ipmicmd._oem.immhandler.get_property(
                '/v2/cmm/sp/7')
            if not bayid:
                return
            #
            self.info['enclosure.bay'] = bayid
            # enclosure.bay only happens for Flex, nextscale doesn't do it
            # this way
        except pygexc.IpmiException as ie:
            print(repr(ie))
            raise


# TODO(jjohnson2): web based init config for future prevalidated cert scheme
#    def config(self, nodename):
#        return

