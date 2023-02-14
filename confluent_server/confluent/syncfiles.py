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
import confluent.util as util
import confluent.noderange as noderange
import eventlet
import pwd
import grp

def mkdirp(path):
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno != 17:
            raise

def get_entries(filename):
    secname = 'REPLACE:'
    filename = filename.strip()
    if filename[-1] == '>':
        filename = filename[:-1]
    with open(filename, 'r') as slfile:
        slist = slfile.read()
    entries = slist.split('\n')
    for ent in entries:
        ent = ent.split('#', 1)[0].strip()
        if not ent:
            continue
        if ent in ('APPENDONCE:', 'MERGE:', 'REPLACE:'):
            secname = ent
        if ent[0] == '<':
            subfilename = ent[1:]
            if subfilename[-1] == '>':
                subfilename = subfilename[:-1]
            if subfilename[0] != '/':
                subfilename = os.path.join(os.path.dirname(filename), subfilename)
            for subent in get_entries(subfilename):
                yield subent
            yield secname
        else:
            yield ent

class SyncList(object):
    def __init__(self, filename, nodename, cfg):
        slist = None
        self.replacemap = {}
        self.appendmap = {}
        self.appendoncemap = {}
        self.mergemap = {}
        self.optmap = {}
        entries = get_entries(filename)
        currmap = self.replacemap
        for ent in entries:
            try:
                cmtidx = ent.index('#')
                ent = ent[:cmtidx]
            except ValueError:
                pass
            for special in '$%^&|{}':
                if special in ent:
                    raise Exception(
                        'Special character "{}" reserved for future use'.format(special))
            ent = ent.strip()
            if not ent:
                continue
            if ent[-1] == ':':
                if ent == 'MERGE:':
                    currmap = self.mergemap
                elif ent == 'APPENDONCE:':
                    currmap = self.appendoncemap
                elif ent == 'REPLACE:':
                    currmap = self.replacemap
                else:
                    raise Exception(
                        'Section "{}" is not currently supported in syncfiles'.format(ent[:-1]))
                continue
            if '->' in ent:
                k, v = ent.split('->')
                k = k.strip()
                v = v.strip()
                if ':' in v:
                    nr, v = v.split(':', 1)
                    try:
                        for candidate in noderange.NodeRange(nr, cfg).nodes:
                            if candidate == nodename:
                                break
                        else:
                            continue
                    except Exception as e:
                        raise Exception('Error on syncfile line "{}": {}'.format(ent, str(e)))
                optparts = v.split()
                v = optparts[0]
                optparts = optparts[1:]
            else:
                kparts = []
                optparts = []
                currparts = kparts
                for part in ent.split():
                    if part[0] == '(':
                        currparts = optparts
                    currparts.append(part)
                k = ' '.join(kparts)
                v = None
            entopts = {}
            if optparts:
                if optparts[0][0] != '(' or optparts[-1][-1] != ')':
                    raise Exception("Unsupported syntax in syncfile: " + ent)
                opts = ','.join(optparts)
                opts = opts[1:-1]
                for opt in opts.split(','):
                    optname, optval = opt.split('=')
                    if optname == 'owner':
                        try:
                            uid = pwd.getpwnam(optval).pw_uid
                        except KeyError:
                            try:
                                uid = int(optval)
                                optval = None
                            except ValueError:
                                uid = None
                        if optval:
                            optval = {'name': optval}
                        else:
                            optval = {}
                        if uid is not None:
                            optval['id'] = uid
                    elif optname == 'group':
                        try:
                            gid = grp.getgrnam(optval).gr_gid
                        except KeyError:
                            try:
                                gid = int(optval)
                                optval = None
                            except ValueError:
                                gid = None
                        if optval:
                            optval = {'name': optval}
                        else:
                            optval = {}
                        if gid is not None:
                            optval['id'] = gid
                    if optval:
                        entopts[optname] = optval
            currmap[k] = v
            targ = v if v else k
            for f in targ.split():
                self.optmap[f] = entopts


def sync_list_to_node(sl, node, suffixes, peerip=None):
    targdir = tempfile.mkdtemp('.syncto{}'.format(node))
    output = ''
    try:
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
                          os.path.join(targdir, suffixes['merge']), True)
        if 'appendonce' in suffixes:
            while suffixes['appendonce'] and suffixes['appendonce'][0] == '/':
                suffixes['appendonce'] = suffixes['appendonce'][1:]
            for ent in sl.appendoncemap:
                stage_ent(sl.appendoncemap, ent,
                          os.path.join(targdir, suffixes['appendonce']), True)
        sshutil.prep_ssh_key('/etc/confluent/ssh/automation')
        targip = node
        if peerip:
            targip = peerip
        output = util.run(
            ['rsync', '-rvLD', targdir + '/', 'root@[{}]:/'.format(targip)])[0]
    except Exception as e:
        if 'CalledProcessError' not in repr(e):
            # https://github.com/eventlet/eventlet/issues/413
            # for some reason, can't catch the calledprocesserror normally
            # for this exception, implement a hack workaround
            raise
        unreadablefiles = []
        for root, dirnames, filenames in os.walk(targdir):
            for filename in filenames:
                filename = os.path.join(root, filename)
                try:
                    with open(filename, 'r') as _:
                        pass
                except OSError as e:
                    unreadablefiles.append(filename.replace(targdir, ''))
        if unreadablefiles:
            raise Exception("Syncing failed due to unreadable files: " + ','.join(unreadablefiles))
        else:
            raise
    finally:
        shutil.rmtree(targdir)
    if not isinstance(output, str):
        output = output.decode('utf8')
    retval = {
        'options': sl.optmap,
        'output': output,
    }
    return retval # need dictionary with output and options

def stage_ent(currmap, ent, targdir, appendexist=False):
    dst = currmap[ent]
    everyfent = []
    allfents = ent.split()
    for tmpent in allfents:
        fents = glob.glob(tmpent)
        if not fents:
            raise Exception('No matching files for "{}"'.format(tmpent))
        everyfent.extend(fents)
    if not everyfent:
        raise Exception('No matching files for "{}"'.format(ent))
    if dst is None:  # this is to indicate source and destination as one
        dst = os.path.dirname(everyfent[0]) + '/'
    while dst and dst[0] == '/':
        dst = dst[1:]
    if len(everyfent) > 1 and dst[-1] != '/':
        raise Exception(
            'Multiple files match {}, {} needs a trailing slash to indicate a directory'.format(ent, dst))
    fulltarg = os.path.join(targdir, dst)
    for targ in everyfent:
        mkpathorlink(targ, fulltarg, appendexist)

def mkpathorlink(source, destination, appendexist=False):
    if os.path.isdir(source):
        mkdirp(destination)
        for ent in os.listdir(source):
            currsrc = os.path.join(source, ent)
            currdst = os.path.join(destination, ent)
            mkpathorlink(currsrc, currdst)
    else:
        if destination[-1] == '/':
            mkdirp(destination)
            destination = os.path.join(destination, os.path.basename(source))
        else:
            mkdirp(os.path.dirname(destination))
        if appendexist and os.path.exists(destination):
            tmphdl, tmpnam = tempfile.mkstemp()
            try:
                shutil.copy(destination, tmpnam)
            finally:
                os.close(tmphdl)
            os.remove(destination)
            with open(destination, 'w') as realdest:
                with open(tmpnam) as olddest:
                    realdest.write(olddest.read())
                with open(source) as sourcedata:
                    realdest.write(sourcedata.read())
            os.remove(tmpnam)
        else:
            if os.path.islink(destination):
                os.remove(destination)
            os.symlink(source, destination)


syncrunners = {}


def start_syncfiles(nodename, cfg, suffixes, principals=[]):
    peerip = None
    if 'myips' in suffixes:
        targips = suffixes['myips']
        del suffixes['myips']
        for targip in targips:
            if targip in principals:
                peerip = targip
                break
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
    sl = SyncList(synclist, nodename, cfg)
    if not (sl.appendmap or sl.mergemap or sl.replacemap or sl.appendoncemap):
        return '200 OK'  # the synclist has no actual entries
    syncrunners[nodename] = eventlet.spawn(
        sync_list_to_node, sl, nodename, suffixes, peerip)
    return '202 Queued' # backgrounded

def get_syncresult(nodename):
    if nodename not in syncrunners:
        return ('204 Not Running', '')
    if not syncrunners[nodename].dead:
        return ('200 OK', '')
    result = syncrunners[nodename].wait()
    del syncrunners[nodename]
    return ('200 OK', result)
