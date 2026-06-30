# Copyright 2026 MEGWARE Computer Vertrieb und Service GmbH
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

"""
OEM handler for Megware EUREKA chassis Redfish service.
"""

import aiohmi.redfish.oem.megware.eureka as eureka


async def get_handler(sysinfo, sysurl, webclient, cache, cmd, rootinfo={}):
    return await eureka.OEMHandler.create(sysinfo, sysurl, webclient, cache, gpool=cmd._gpool)
