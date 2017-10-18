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

import confluent.exceptions as exc
import confluent.messages as msg
import eventlet

updatesbytarget = {}

def execupdate(handler, filename, updateobj):
    try:
        completion = handler(filename, progress=updateobj.handle_progress,
                             bank=updateobj.bank)
        if completion is None:
            completion = 'complete'
        updateobj.handle_progress({'phase': completion, 'progress': 100.0})
    except exc.PubkeyInvalid as pi:
        errstr = 'Certificate mismatch detected, does not match value in ' \
                 'attribute {0}'.format(pi.attrname)
        updateobj.handle_progress({'phase': 'error', 'progress': 0.0,
                                   'detail': errstr})
    except Exception as e:
        updateobj.handle_progress({'phase': 'error', 'progress': 0.0,
                                   'detail': str(e)})

class Updater(object):
    def __init__(self, node, handler, filename, tenant=None, name=None,
                 bank=None):
        self.bank = bank
        self.node = node
        self.phase = 'initializing'
        self.detail = ''
        self.percent = 0.0
        self.updateproc = eventlet.spawn(execupdate, handler, filename, self)
        if (node, tenant) not in updatesbytarget:
            updatesbytarget[(node, tenant)] = {}
        if name is None:
            name = 1
            while '{0}'.format(name) in updatesbytarget[(node, tenant)]:
                name += 1
        self.name = '{0}'.format(name)
        updatesbytarget[(node, tenant)][self.name] = self

    def handle_progress(self, progress):
        self.phase = progress['phase']
        self.percent = float(progress['progress'])
        self.detail = progress.get('detail', '')

    def cancel(self):
        self.updateproc.kill()

    @property
    def progress(self):
        return {'phase': self.phase, 'progress': self.percent,
                'detail': self.detail}


def remove_updates(nodes, tenant, element):
    if len(element) < 5:
        raise exc.InvalidArgumentException()
    upid = element[-1]
    for node in nodes:
        try:
            upd = updatesbytarget[(node, tenant)][upid]
        except KeyError:
            raise exc.NotFoundException('No active update matches request')
        upd.cancel()
        del updatesbytarget[(node, tenant)][upid]
        yield msg.DeletedResource(
            'nodes/{0}/inventory/firmware/updates/active/{1}'.format(
                node, upid))


def list_updates(nodes, tenant, element):
    showmode = False
    if len(element) > 4:
        showmode = True
        upid = element[-1]
    for node in nodes:
        if showmode:
            try:
                updater = updatesbytarget[(node, tenant)][upid]
            except KeyError:
                raise exc.NotFoundException('No matching update process found')
            yield msg.KeyValueData(updater.progress, name=node)
        else:
            for updateid in updatesbytarget.get((node, tenant), {}):
                yield msg.ChildCollection(updateid)
