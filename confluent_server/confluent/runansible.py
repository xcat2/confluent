#!/usr/bin/python
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

try:
    import confluent.sshutil as sshutil
    import confluent.tasks as tasks
except ImportError:
    pass
import asyncio
import base64
import shutil
import json
import socket
import msgpack
import os
import struct
import sys
import tempfile

anspypath = None
running_status = {}

async def recv_exact(conn, size):
    data = b''
    while len(data) < size:
        chunk = await asyncio.get_running_loop().sock_recv(conn, size - len(data))
        if not chunk:
            return None
        data += chunk
    return data

async def recv_message(conn):
    header = await recv_exact(conn, 8)
    if not header:
        return None
    sz = struct.unpack('=q', header)[0]
    msg = await recv_exact(conn, sz)
    if not msg:
        return None
    return msgpack.unpackb(msg, raw=False)


class _AttribTree(dict):
    # a level of nest_attributes, as opposed to a dict attribute value
    pass


def nest_attributes(attribs):
    # turn dotted attribute names into nested dicts, like hand written
    # host_vars. A name that is also the prefix of other names keeps its
    # value under '_value'
    tree = _AttribTree()
    conflicts = []
    # sorting puts a name before any name it is a prefix of
    for attrib in sorted(attribs):
        parts = attrib.split('.')
        currdict = tree
        for idx, part in enumerate(parts[:-1]):
            if part in currdict and not isinstance(currdict[part], _AttribTree):
                currdict[part] = _AttribTree(_value=currdict[part])
                conflicts.append(
                    '{0} is also a prefix of other attributes, its value is '
                    'available as confluent{1}'.format(
                        '.'.join(parts[:idx + 1]),
                        ''.join("['{0}']".format(x) for x in
                                parts[:idx + 1] + ['_value'])))
            currdict = currdict.setdefault(part, _AttribTree())
        if parts[-1] in currdict:
            # only an attribute named _value can collide like this
            conflicts.append('{0} is left out, its name holds the value of '
                             '{1}'.format(attrib, '.'.join(parts[:-1])))
            continue
        currdict[parts[-1]] = attribs[attrib]
    return tree, conflicts


def get_hostvars(cfg, node):
    attribs = {}
    nodeattribs = cfg.get_node_attributes(node, decrypt=False).get(node, {})
    for attrib, data in nodeattribs.items():
        if attrib.startswith(('secret.', 'crypted.', 'custom.nodesecret.')):
            continue
        if isinstance(data, dict):
            # skip unset values, like /self/myattribs does
            data = data.get('value')
            if not data:
                continue
        if isinstance(data, bytes):
            data = data.decode()
        attribs[attrib] = data
    return nest_attributes(attribs)


class PlayRunner(object):
    def __init__(self, playfiles, nodes, hostvars=None):
        self.stderr = ''
        self.playfiles = playfiles
        self.nodes = nodes
        self.hostvars = hostvars if hostvars else {}
        self.worker = None
        self.results = []
        self.complete = False
        self.stdout = ''

    def _start_playbooks(self):
        self.worker = tasks.spawn(self._really_run_playbooks())

    def get_available_results(self):
        avail = self.results
        self.results = []
        return avail

    def dump_text(self):
        stderr = self.stderr
        stdout = self.stdout
        retinfo = self.dump_dict()
        textout = ''
        for result in retinfo['results']:
            textout += 'TASK [{}] *******************************\n'.format(
                result['task_name'])
            for warning in result['warnings']:
                textout += '[WARNING]: ' + warning + '\n'
            if 'errorinfo' in result:
                textout += '{} => {}\n'.format(result['state'],
                                                result['errorinfo'])
            else:
                if result['changed']:
                    textout += 'changed\n'
                else:
                    textout += result['state'] + '\n'
            textout += '\n'
        if stdout:
            textout += "OUTPUT **********************************\n"
            textout += stdout
        if stderr:
            textout += "ERRORS **********************************\n"
            textout += stderr
        return textout

    def dump_json(self):
        return json.dumps(self.dump_dict())

    def dump_dict(self):
        return {
            'complete': self.complete,
            'results': self.get_available_results()
        }
    async def _really_run_playbooks(self):
        global anspypath
        try:
            mypath = anspypath
            if not mypath:
                ansloc = shutil.which('ansible')
                if ansloc:
                    with open(ansloc, 'r') as onsop:
                        shebang = onsop.readline()
                        anspypath = shebang.strip().replace('#!', '').strip()
                        mypath = anspypath
            if not mypath:
                mypath = sys.executable
            targnodes = ','.join(self.nodes)
            with tempfile.TemporaryDirectory() as tmpdir:
                feedback = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                suffix = base64.urlsafe_b64encode(os.urandom(6)).decode('utf8')
                sockpath = os.path.join(tmpdir, 'feedback-' + suffix)
                feedback.bind(sockpath)
                feedback.listen(1)
                feedback.setblocking(False)
                localenv = os.environ.copy()
                localenv['FEEDBACK_SOCK'] = sockpath
                hostvarspath = os.path.join(tmpdir, 'hostvars.json')
                with open(os.open(hostvarspath, os.O_WRONLY | os.O_CREAT, 0o600),
                          'w') as hostvarsout:
                    json.dump(self.hostvars, hostvarsout, default=str)
                localenv['CONFLUENT_HOSTVARS'] = hostvarspath
                # ANSIBLE_SSH_ARGS replaces ansible's ssh_args, so start from
                # its defaults to keep ControlPersist
                ansiblesshargs = os.environ.get(
                    'ANSIBLE_SSH_ARGS', '-C -o ControlMaster=auto -o ControlPersist=60s')
                # limit host based algorithms to avoid excessive authentication attempts
                if 'hostbasedkeytypes' not in ansiblesshargs.lower() and 'hostbasedacceptedalgorithms' not in ansiblesshargs.lower():
                    ansiblesshargs += ' -o HostbasedAcceptedAlgorithms=*ed25519*'
                # notice a node that was reset mid play, else ssh waits forever
                if 'serveraliveinterval' not in ansiblesshargs.lower():
                    ansiblesshargs += ' -o ServerAliveInterval=15 -o ServerAliveCountMax=4'
                localenv['ANSIBLE_SSH_ARGS'] = ansiblesshargs
                # feed modules over the ssh session rather than copying them over first
                if 'ANSIBLE_PIPELINING' not in localenv and 'ANSIBLE_SSH_PIPELINING' not in localenv:
                    localenv['ANSIBLE_PIPELINING'] = 'True'
                with feedback:
                    for playfilename in self.playfiles:
                        worker = await asyncio.create_subprocess_exec(
                            mypath, __file__, targnodes, playfilename,
                            stdin=asyncio.subprocess.DEVNULL,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                            env=localenv)
                        # drain output so a full pipe cannot block the play
                        outreader = asyncio.ensure_future(worker.stdout.read())
                        errreader = asyncio.ensure_future(worker.stderr.read())
                        exiter = asyncio.ensure_future(worker.wait())
                        accepter = asyncio.ensure_future(
                            asyncio.get_running_loop().sock_accept(feedback))
                        await asyncio.wait((accepter, exiter),
                                           return_when=asyncio.FIRST_COMPLETED)
                        conn = None
                        if accepter.done():
                            conn, _ = accepter.result()
                        else:
                            # exited before or right after connecting
                            accepter.cancel()
                            try:
                                conn, _ = feedback.accept()
                            except BlockingIOError:
                                pass
                        if conn:
                            conn.setblocking(False)
                            try:
                                result = True
                                while result is not None:
                                    result = await recv_message(conn)
                                    if result:
                                        self.results.append(result)
                                    if worker.returncode is not None:
                                        break
                                while result:
                                    result = await recv_message(conn)
                                    if result is not None:
                                        self.results.append(result)
                            finally:
                                conn.close()
                        await exiter
                        stdout = await outreader
                        stder = await errreader
                        self.stderr += stder.decode('utf8')
                        self.stdout += stdout.decode('utf8')
                        if worker.returncode != 0:
                            # the play could not run at all
                            errlines = stder.decode('utf8').strip().splitlines()
                            self.results.append({
                                'task_name': os.path.basename(playfilename),
                                'changed': False, 'state': 'FAILED',
                                'warnings': [],
                                'errorinfo': '\n'.join(errlines[-10:])})
        finally:
            self.complete = True


async def run_playbooks(playfiles, nodes, cfg=None):
    await sshutil.prep_ssh_key('/etc/confluent/ssh/automation')
    hostvars = {}
    conflicts = []
    if cfg is not None:
        for node in nodes:
            hostvars[node], nodeconflicts = get_hostvars(cfg, node)
            conflicts.extend(nodeconflicts)
    runner = PlayRunner(playfiles, nodes, hostvars)
    if conflicts:
        runner.results.append({
            'task_name': 'confluent host variables', 'changed': False,
            'state': 'ok', 'warnings': conflicts})
    for node in nodes:
        running_status[node] = runner
    runner._start_playbooks()


def print_result(result, state, collector=None, callbacksock=None):
    # _result is deprecated in newer ansible-core
    taskresult = getattr(result, 'result', None)
    if taskresult is None:
        taskresult = result._result
    output = {
        'task_name': result.task_name,
        'changed': taskresult.get('changed', ''),
    }
    output['state'] = state
    output['warnings'] = taskresult.get('warnings', [])
    try:
        del taskresult['warnings']
    except KeyError:
        pass
    if state != 'ok' and collector and hasattr(collector, '_dump_results'):
        output['errorinfo'] = collector._dump_results(taskresult)
    msg = msgpack.packb(output, use_bin_type=True)
    msglen = len(msg)
    callbacksock.sendall(struct.pack('=q', msglen))
    callbacksock.sendall(msg)

if __name__ == '__main__':
    from ansible.inventory.manager import InventoryManager
    from ansible.parsing.dataloader import DataLoader
    from ansible.executor.task_queue_manager import TaskQueueManager
    from ansible.vars.manager import VariableManager
    from ansible.playbook.play import Play
    from ansible import context
    from ansible.module_utils.common.collections import ImmutableDict
    from ansible.plugins.callback import CallbackBase
    import ansible.plugins.loader
    import inspect

    sockpath = os.environ.get('FEEDBACK_SOCK')
    if not sockpath:
        sys.stderr.write('No feedback socket specified\n')
        sys.exit(1)

    callbacksock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    callbacksock.connect(sockpath)


    class ResultsCollector(CallbackBase):
        # used in ansible's callback error messages
        _load_name = 'confluent'

        def v2_runner_on_unreachable(self, result):
            print_result(result, 'UNREACHABLE', self, callbacksock)

        def v2_runner_on_ok(self, result, *args, **kwargs):
            print_result(result, 'ok', self, callbacksock)

        def v2_runner_on_failed(self, result, *args, **kwargs):
            print_result(result, 'FAILED', self, callbacksock)

    context.CLIARGS = ImmutableDict(
        connection='smart', module_path=['/usr/share/ansible'], forks=10,
        become=None, become_method=None, become_user=None, check=False,
        diff=False, verbosity=0, remote_user='root')

    try:
        ansible.plugins.loader.init_plugin_loader()
    except AttributeError:
        pass
    loader = DataLoader()
    invman = None
    if os.path.exists('/etc/ansible/hosts'):
        aninv = InventoryManager(loader=loader, sources='/etc/ansible/hosts')
        anshost = aninv.get_host(sys.argv[1])
        if not anshost:
            aninv.add_host(sys.argv[1])
        invman = aninv
    if not invman:
        invlist = sys.argv[1] + ','
        invman = InventoryManager(loader=loader, sources=invlist)
    hostvarspath = os.environ.get('CONFLUENT_HOSTVARS')
    if hostvarspath:
        import ansible.template
        if hasattr(ansible.template, 'trust_as_template'):
            # ansible-core 2.19+ never templates untrusted data
            wrap_var = lambda x: x
        else:
            from ansible.utils.unsafe_proxy import wrap_var
        with open(hostvarspath, 'r') as hostvarsin:
            hostvars = json.load(hostvarsin)
        for hostname in hostvars:
            anshost = invman.get_host(hostname)
            if anshost:
                # attribute values are data, never templates
                anshost.set_variable('confluent', wrap_var(hostvars[hostname]))
    varman = VariableManager(loader=loader, inventory=invman)
    if 'trusted_as_template' in inspect.signature(
            loader.load_from_file).parameters:
        # ansible-core 2.19+ only templates trusted data
        plays = loader.load_from_file(sys.argv[2], trusted_as_template=True)
    else:
        plays = loader.load_from_file(sys.argv[2])
    os.chdir(os.path.dirname(sys.argv[2]))
    if isinstance(plays, dict):
        plays = [plays]
    callbackbyname = 'stdout_callback_name' in inspect.signature(
        TaskQueueManager.__init__).parameters

    for currplay in plays:
        collector = ResultsCollector()
        # newer ansible-core only takes a callback name
        callbackarg = {} if callbackbyname else {'stdout_callback': collector}
        taskman = TaskQueueManager(inventory=invman, loader=loader, passwords={},
            variable_manager=varman, **callbackarg)
        if callbackbyname:
            # ansible then loads none of its own
            collector._init_callback_methods()
            taskman._callback_plugins.append(collector)

        currplay['hosts'] = sys.argv[1]
        if 'become' in currplay and 'become_user' not in currplay:
            del currplay['become']
        play = Play().load(currplay, loader=loader)
        try:
            taskman.run(play)
        finally:
            taskman.cleanup()
            if loader:
                loader.cleanup_all_tmp_files()
