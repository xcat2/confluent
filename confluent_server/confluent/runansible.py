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
class PlayRunner(object):
    def __init__(self, playfiles, nodes):
        self.stderr = ''
        self.playfiles = playfiles
        self.nodes = nodes
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
                        anspypath = shebang.strip().replace('#!', '')
                        mypath = anspypath
            if not mypath:
                mypath = sys.executable
            targnodes = ','.join(self.nodes)
            for playfilename in self.playfiles:
                worker = await asyncio.create_subprocess_exec(
                    mypath, __file__, targnodes, playfilename,
                    stdin=asyncio.subprocess.DEVNULL,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE)
                stdout, stder = await worker.communicate()
                self.stderr += stder.decode('utf8')
                current = memoryview(stdout)
                while len(current):
                    sz = struct.unpack('=q', current[:8])[0]
                    result = msgpack.unpackb(current[8:8+sz], raw=False)
                    self.results.append(result)
                    current = current[8+sz:]
        finally:
            self.complete = True


def run_playbooks(playfiles, nodes):
    sshutil.prep_ssh_key('/etc/confluent/ssh/automation')
    runner = PlayRunner(playfiles, nodes)
    for node in nodes:
        running_status[node] = runner
    runner._start_playbooks()


def print_result(result, state, collector=None, callbacksock=None):
    output = {
        'task_name': result.task_name,
        'changed': result._result.get('changed', ''),
    }
    output['state'] = state
    output['warnings'] = result._result.get('warnings', [])
    try:
        del result._result['warnings']
    except KeyError:
        pass
    if state != 'ok' and collector and hasattr(collector, '_dump_results'):
        output['errorinfo'] = collector._dump_results(result._result)
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
    import yaml

    sockpath = os.environ.get('FEEDBACK_SOCK')
    if not sockpath:
        sys.stderr.write('No feedback socket specified\n')
        sys.exit(1)

    callbacksock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    callbacksock.connect(sockpath)


    class ResultsCollector(CallbackBase):

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
    varman = VariableManager(loader=loader, inventory=invman)
    plays = yaml.safe_load(open(sys.argv[2]))
    os.chdir(os.path.dirname(sys.argv[2]))
    if isinstance(plays, dict):
        plays = [plays]

    for currplay in plays:
        taskman = TaskQueueManager(inventory=invman, loader=loader, passwords={},
            variable_manager=varman, stdout_callback=ResultsCollector())

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
