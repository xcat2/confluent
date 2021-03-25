# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2021 Lenovo
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

import glob
import os
import shutil
import tempfile
import confluent.sshutil as sshutil
import eventlet.green.subprocess as subprocess
import eventlet

def mkdirp(path):
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno != 17:
            raise

class SyncList(object):
    def __init__(self, filename):
        slist = None
        self.replacemap = {}
        self.appendmap = {}
        self.mergemap = {}
        with open(filename, 'r') as slfile:
            slist = slfile.read()
        entries = slist.split('\n')
        currmap = self.replacemap
        for ent in entries:
            try:
                cmtidx = ent.index('#')
                ent = ent[:cmtidx]
            except ValueError:
                pass
            for special in '!@$%^&*()|{}':
                if special in ent:
                    raise Exception(
                        'Special character "{}" reserved for future use'.format(special))
            ent = ent.strip()
            if not ent:
                continue
            if ent[-1] == ':':
                if ent == 'APPEND:':
                    currmap = self.appendmap
                elif ent == 'MERGE:':
                    currmap = self.mergemap
                else:
                    raise Exception(
                        'Section "{}" is not currently supported in syncfiles'.format(ent[:-1]))
                continue
            if '->' in ent:
                k, v = ent.split('->')
                k = k.strip()
                v = v.strip()
            else:
                k = ent
                v = ent
            currmap[k] = v


def sync_list_to_node(synclist, node, suffixes):
    targdir = tempfile.mkdtemp('.syncto{}'.format(node))
    output = ''
    try:
        sl = SyncList(synclist)
        for ent in sl.replacemap:
            stage_ent(sl.replacemap, ent, targdir)
        if 'append' in suffixes:
            while suffixes['append'] and suffixes['append'][0] == '/':
                suffixes['append'] = suffixes['append'][1:]
            for ent in sl.appendmap:
                stage_ent(sl.appendmap, ent,
                          os.path.join(targdir, suffixes['append']))
        if 'merge' in suffixes:
            while suffixes['merge'] and suffixes['merge'][0] == '/':
                suffixes['merge'] = suffixes['merge'][1:]
            for ent in sl.mergemap:
                stage_ent(sl.mergemap, ent,
                          os.path.join(targdir, suffixes['merge']))
        sshutil.prep_ssh_key('/etc/confluent/ssh/automation')
        output = subprocess.check_output(
            ['rsync', '-aL', targdir + '/', 'root@{}:/'.format(node)])
    finally:
        shutil.rmtree(targdir)
    return output

def stage_ent(currmap, ent, targdir):
    dst = currmap[ent]
    everyfent = []
    allfents = ent.split()
    for tmpent in allfents:
        fents = glob.glob(tmpent)
        if fents:
            everyfent.extend(fents)
        else:
            everyfent.extend(os.path.dirname(tmpent))
    if not everyfent:
        raise Exception('No matching files for "{}"'.format(ent))
    while dst and dst[0] == '/':
        dst = dst[1:]
    fulltarg = os.path.join(targdir, dst)
    if dst[-1] == '/' or len(everyfent) > 1 or os.path.isdir(everyfent[0]):
        # target *must* be a directory
        fulltargdir = fulltarg
    else:
        fulltargdir = os.path.join(targdir, os.path.dirname(dst))
    mkdirp(fulltargdir)
    for targ in everyfent:
        if fulltargdir == fulltarg:
            os.symlink(
                targ, os.path.join(
                    fulltargdir, os.path.basename(targ)))
        else:
            os.symlink(targ, fulltarg)

syncrunners = {}


def start_syncfiles(nodename, cfg, suffixes):
    deployinfo = cfg.get_node_attributes(
        nodename, ('deployment.*',))
    deployinfo = deployinfo.get(nodename, {})
    profile = deployinfo.get(
        'deployment.pendingprofile', {}).get('value', '')
    if not profile:
        profile = deployinfo.get(
        'deployment.stagedprofile', {}).get('value', '')
    if not profile:
        profile = deployinfo.get(
        'deployment.profile', {}).get('value', '')
    if not profile:
        raise Exception('Cannot perform syncfiles without profile assigned')
    synclist = '/var/lib/confluent/public/os/{}/syncfiles'.format(profile)
    if not os.path.exists(synclist):
        return '200 OK'  # not running
    syncrunners[nodename] = eventlet.spawn(
        sync_list_to_node, synclist, nodename, suffixes)
    return '202 Queued' # backgrounded

def get_syncresult(nodename):
    if nodename not in syncrunners:
        return ('204 Not Running', '')
    if not syncrunners[nodename].dead:
        return ('200 OK', '')
    result = syncrunners[nodename].wait()
    del syncrunners[nodename]
    return ('200 OK', result)
