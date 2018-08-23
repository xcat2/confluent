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
import os
import socket

updatesbytarget = {}
uploadsbytarget = {}
downloadsbytarget = {}
updatepool = eventlet.greenpool.GreenPool(256)


def execupdate(handler, filename, updateobj, type):
    if type != 'ffdc' and not os.path.exists(filename):
        errstr =  '{0} does not appear to exist on {1}'.format(
            filename, socket.gethostname())
        updateobj.handle_progress({'phase': 'error', 'progress': 0.0,
                                   'detail': errstr})
    try:
        if type == 'firmware':
            completion = handler(filename, progress=updateobj.handle_progress,
                                 bank=updateobj.bank)
        else:
            completion = handler(filename, progress=updateobj.handle_progress)
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
                 bank=None, type='firmware'):
        self.bank = bank
        self.node = node
        self.phase = 'initializing'
        self.detail = ''
        self.percent = 0.0
        self.updateproc = updatepool.spawn(execupdate, handler, filename,
                                           self, type)
        if type == 'firmware':
            myparty = updatesbytarget
        elif type == 'mediaupload':
            myparty = uploadsbytarget
        elif type == 'ffdc':
            myparty = downloadsbytarget
        if (node, tenant) not in myparty:
            myparty[(node, tenant)] = {}
        if name is None:
            name = 1
            while '{0}'.format(name) in myparty[(node, tenant)]:
                name += 1
        self.name = '{0}'.format(name)
        myparty[(node, tenant)][self.name] = self

    def handle_progress(self, progress):
        self.phase = progress.get('phase', 'unknown')
        self.percent = float(progress.get('progress', 100.0))
        self.detail = progress.get('detail', '')

    def cancel(self):
        self.updateproc.kill()

    @property
    def progress(self):
        return {'phase': self.phase, 'progress': self.percent,
                'detail': self.detail}


def remove_updates(nodes, tenant, element, type='firmware'):
    if len(element) < 5 and element[:2] != ['media', 'uploads']:
        raise exc.InvalidArgumentException()
    upid = element[-1]
    if type == 'firmware':
        myparty = updatesbytarget
    elif type == 'ffdc':
        myparty = downloadsbytarget
    else:
        myparty = uploadsbytarget
    for node in nodes:
        try:
            upd = myparty[(node, tenant)][upid]
        except KeyError:
            raise exc.NotFoundException('No active update matches request')
        upd.cancel()
        del myparty[(node, tenant)][upid]
        yield msg.DeletedResource(
            'nodes/{0}/inventory/firmware/updates/active/{1}'.format(
                node, upid))


def list_updates(nodes, tenant, element, type='firmware'):
    showmode = False
    if type == 'mediaupload':
        myparty = uploadsbytarget
        verb = 'upload'
    elif type == 'ffdc':
        verb = 'download'
        myparty = downloadsbytarget
    else:
        myparty = updatesbytarget
        verb = 'update'
    if type == 'firmware':
        specificlen = 4
    else:
        specificlen = 2
    if len(element) > specificlen:
        showmode = True
        upid = element[-1]
    for node in nodes:
        if showmode:
            try:
                updater = myparty[(node, tenant)][upid]
            except KeyError:
                raise exc.NotFoundException(
                    'No matching {0} process found'.format(verb))
            yield msg.KeyValueData(updater.progress, name=node)
        else:
            for updateid in myparty.get((node, tenant), {}):
                yield msg.ChildCollection(updateid)
