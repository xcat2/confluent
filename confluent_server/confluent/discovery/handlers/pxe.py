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

# This contains functionality for passive detection and, one day, active
# response to pxe


import confluent.discovery.handlers.generic as generic

class NodeHandler(generic.NodeHandler):
    https_supported = False
    is_enclosure = False
    devname = 'PXE'

    def __init__(self, info, configmanager):
        self._ipaddr = ''
        self.cfm = configmanager

    @property
    def cert_fail_reason(self):
        return 'unsupported'

    @property
    def https_cert(self):
        return None

    def config(self, nodename):
        return
