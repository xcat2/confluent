# vim: tabstop=4 shiftwidth=4 softtabstop=4


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

# provide managing firmware update process and firmware repository if/when
# the time comes

import confluent.messages as msg
import eventlet

updatesbytarget = {}

def execupdate(handler, filename, updateobj):
    try:
        handler(filename, progress=updateobj.handle_progress)
        updateobj.handle_progress({'phase': 'complete', 'progress': 100.0})
    except Exception as e:
        updateobj.handle_progress({'phase': 'error', 'progress': 0.0,
                                   'detail': repr(e)})

class Updater(object):
    def __init__(self, node, handler, filename, tenant=None, name=None):
        self.node = node
        self.phase = 'initializing'
        self.percent = 0.0
        self.updateproc = eventlet.spawn(execupdate, handler, filename, self)
        if (node, tenant) not in updatesbytarget:
            updatesbytarget[(node, tenant)] = {}
        if name is None:
            name = 1
            while name in updatesbytarget[(node, tenant)]:
                name += 1
        updatesbytarget[(node, tenant)][name] = self

    def handle_progress(self, progress):
        self.phase = progress['phase']
        self.percent = float(progress['progress'])
        self.detail = progress.get('detail', '')

    @property
    def progress(self):
        return {'phase': self.phase, 'progress': self.percent,
                'detail': self.detail}


def list_updates(nodes, tenant=None):
    for node in nodes:
        for updateid in updatesbytarget.get((node, None), {}):
            yield msg.ChildCollection(updateid)
