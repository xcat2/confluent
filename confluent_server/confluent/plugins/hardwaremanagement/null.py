# Copyright 2026 Lenovo
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

# A do-nothing hardware management plugin that reports that every
# requested operation is not implemented.

import confluent.messages as msg



async def _notimplemented(nodes, element, configmanager, inputdata):
    if not nodes:
        nodes = [None]
    for node in nodes:
        yield msg.NotImplemented(node)


retrieve = _notimplemented
update = _notimplemented
create = _notimplemented
delete = _notimplemented
