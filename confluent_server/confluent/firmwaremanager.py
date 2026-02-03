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
import confluent.log as log
import confluent.messages as msg
import confluent.tasks as tasks
import io
import os
import pwd
import socket
import traceback

updatesbytarget = {}
uploadsbytarget = {}
downloadsbytarget = {}
_tracelog = None
sharedfiles = {}
updatepool = tasks.TaskPool(max_concurrent=256)


async def execupdate(handler, filename, updateobj, type, owner, node, datfile):
    global _tracelog
    try:
        if type != 'ffdc' and not datfile:
            errstr = False
            if not os.path.exists(filename):
                errstr =  '{0} does not appear to exist on {1}, or is in a directory with permissions forbidding confluent user/group access'.format(
                    filename, socket.gethostname())
            elif not os.access(filename, os.R_OK):
                errstr =  '{0} is not readable by confluent on {1} (ensure confluent user or group can access file and parent directories)'.format(
                    filename, socket.gethostname())
            if errstr:
                updateobj.handle_progress({'phase': 'error', 'progress': 0.0,
                                        'detail': errstr})
                return
        if type == 'ffdc' and os.path.isdir(filename):
            filename += '/' + node
        if type == 'ffdc':
            errstr = False
            if os.path.exists(filename):
                errstr = '{0} already exists on {1}, cannot overwrite'.format(
                    filename, socket.gethostname())
            elif not os.access(os.path.dirname(filename), os.W_OK):
                errstr = '{0} directory not writable by confluent user/group on {1}, check the directory and parent directory ownership and permissions'.format(filename, socket.gethostname())
            if errstr:
                updateobj.handle_progress({'phase': 'error', 'progress': 0.0,
                                        'detail': errstr})
                return
        try:
            if type == 'firmware':
                completion = await handler(filename, progress=updateobj.handle_progress,
                                    data=datfile, bank=updateobj.bank)
            else:
                completion = await handler(filename, progress=updateobj.handle_progress,
                                    data=datfile)
            if type == 'ffdc' and completion:
                filename = completion
                completion = None
            if completion is None:
                completion = 'complete'
            if owner:
                pwent = pwd.getpwnam(owner)
                try:
                    os.chown(filename, pwent.pw_uid, pwent.pw_gid)
                except:
                    raise Exception('Error changing ownership of {} to {}, file is complete but owned by confluent instead'.format(filename, owner))
            updateobj.handle_progress({'phase': completion, 'progress': 100.0})
        except exc.PubkeyInvalid as pi:
            errstr = 'Certificate mismatch detected, does not match value in ' \
                    'attribute {0}'.format(pi.attrname)
            updateobj.handle_progress({'phase': 'error', 'progress': 0.0,
                                    'detail': errstr})
        except Exception as e:
            if _tracelog is None:
                _tracelog = log.Logger('trace')
            _tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event, event=log.Events.stacktrace)
            updateobj.handle_progress({'phase': 'error', 'progress': 0.0,
                                    'detail': str(e)})
    finally:
        if filename in sharedfiles:
            if sharedfiles[filename][0] == 1:
                del sharedfiles[filename]
            else:
                sharedfiles[filename][0] -= 1


class Updater(object):
    def __init__(self, node, handler, filename, tenant=None, name=None,
                 bank=None, type='firmware', owner=None, configmanager=None):
        self.bank = bank
        self.node = node
        self.phase = 'initializing'
        self.detail = ''
        self.percent = 0.0
        if configmanager and filename in configmanager.clientfiles:
            if filename in sharedfiles:
                sharedfiles[filename][0] += 1
            else:
                cf = configmanager.clientfiles[filename]
                datfile = os.fdopen(os.dup(cf.fileno()), cf.mode)
                sharedfiles[filename] = [1, datfile.read()]
                datfile.close()
            datfile = io.BytesIO(sharedfiles[filename][1])
        else:
            datfile = None
        self.datfile = datfile
        self.updateproc = updatepool.schedule(execupdate, handler, filename,
                                           self, type, owner, node, datfile)
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
        self.updateproc.cancel()
        if self.datfile:
            self.datfile.close()

    @property
    def progress(self):
        return {'phase': self.phase, 'progress': self.percent,
                'detail': self.detail}


def remove_updates(nodes, tenant, element, type='firmware'):
    if len(element) < 5 and element[:2] not in (['media', 'uploads'], ['support', 'servicedata']):
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
