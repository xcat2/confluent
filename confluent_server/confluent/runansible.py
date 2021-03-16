#!/usr/bin/python
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
# Copyright 2015-2018 Lenovo
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
except ImportError:
    pass
import eventlet.green.subprocess as subprocess
import msgpack
import os
import sys

running_status = {}

def run_playbooks(playfiles, nodes):
    sshutil.prep_ssh_key('/etc/confluent/ssh/automation')
    targnodes = ','.join(nodes)
    for playfilename in playfiles:
        worker = subprocess.Popen(
            [sys.executable, __file__, targnodes, playfilename])
        for node in nodes:
            running_status[node] = worker


if __name__ == '__main__':
    from ansible.inventory.manager import InventoryManager
    from ansible.parsing.dataloader import DataLoader
    from ansible.executor.task_queue_manager import TaskQueueManager
    from ansible.vars.manager import VariableManager
    from ansible.playbook.play import Play
    from ansible import context
    from ansible.module_utils.common.collections import ImmutableDict
    from ansible.plugins.callback import CallbackBase
    import yaml

    class ResultsCollector(CallbackBase):
        def v2_runner_on_unreachable(self, result):
            print(dir(result))
            print(repr(result._result))

        def v2_runner_on_ok(self, result, *args, **kwargs):
            print(repr(result))
            print(repr(result.task_name))
            print(repr(result.is_changed()))
            print(repr(result.is_skipped()))
            print(repr(result.is_failed()))
            print(repr(result.is_unreachable()))
            print(dir(result))
            print(repr(result._result))
            print(repr(args))
            print(repr(kwargs))

        def v2_runner_on_failed(self, result, *args, **kwargs):
            print(repr(result))
            print(repr(args))
            print(repr(kwargs))

    context.CLIARGS = ImmutableDict(
        connection='smart', module_path=['/usr/share/ansible'], forks=10,
        become=None, become_method=None, become_user=None, check=False,
        diff=False, verbosity=0, remote_user='root')


    invlist = sys.argv[1] + ','
    loader = DataLoader()
    invman = InventoryManager(loader=loader, sources=invlist)
    varman = VariableManager(loader=loader, inventory=invman)

    plays = yaml.safe_load(open(sys.argv[2]))
    if isinstance(plays, dict):
        plays = [plays]
    taskman = TaskQueueManager(inventory=invman, loader=loader, passwords={},
        variable_manager=varman, stdout_callback=ResultsCollector())
    for currplay in plays:
        currplay['hosts'] = sys.argv[1]
        play = Play().load(currplay, loader=loader)
        try:
            taskman.run(play)
        finally:
            taskman.cleanup()
            if loader:
                loader.cleanup_all_tmp_files()
