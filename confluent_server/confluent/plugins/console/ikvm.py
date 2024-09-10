# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2024 Lenovo
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


# This provides linkage between vinz and confluent, with support
# for getting session authorization from the BMC

import confluent.vinzmanager as vinzmanager
import confluent.messages as msg


async def create(nodes, element, configmanager, inputdata):
    for node in nodes:
        url = await vinzmanager.get_url(node, inputdata)
        yield msg.ChildCollection(url)


async def update(nodes, element, configmanager, inputdata):
    for node in nodes:
        url = await vinzmanager.get_url(node, inputdata)
        yield msg.ChildCollection(url)
