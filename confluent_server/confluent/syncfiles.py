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


def mkdirp(path):
    try:
        os.makedirs(path)
    except OSError as e:
        if errno != 17:
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
            ent = ent.strip()
            if ent[-1] == ':':
                if ent == 'APPEND':
                    currmap = self.appendmap
                elif ent == 'MERGE':
                    currmap = self.mergemap
                else:
                    raise Exception(
                        'Section "{}" is not currently supported in syncfiles'.format(ent[:-1]))
            if '->' in ent:
                k, v = ent.split('->')
                k = k.strip()
                v = v.strip()
            else:
                k = ent
                v = ent
            currmap[k] = v


def sync_list_to_node(synclist, node):
    targdir = tempfile.mkdtemp('.syncto{}'.format(node))
    try:
        sl = SyncList(synclist)
        for ent in sl.replacemap:
            dst = sl.replacemap[ent]
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
    finally:
        shutil.rmtree(targdir)
