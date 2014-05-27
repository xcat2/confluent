# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
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

# This implements a plugin factory to produce plugin objects from shell scripts
# For now, this only is intended to support scripts to implement console
# Special comment fields shall be used to request anything like config
# data and config data will be passed in as environment variables.
# at least in linux, this is a safe enough practice since environ is readable
# only by the process owner and such an owner would be able to read a file
# anyway.  Regardless, it is advisable to 'unset'

import confluent.interface.console as conapi
import eventlet
import eventlet.green.select as select
import eventlet.green.subprocess as subprocess
import fcntl
import os
import pty
import random
import subprocess


class ExecConsole(conapi.Console):
    def __init__(self, executable, node):
        self.executable = executable
        self.subenv = {
            'TERM': 'xterm',
            'CONFLUENT_NODE': node,
        }

    def relaydata(self):
        while 1:
            select.select(
                (self._master, self.subproc.stderr), (), (),
                3600 + (random.random() * 120))
            try:
                while 1:
                    self._datacallback(os.read(self._master, 128))
                    eventlet.sleep(0)
            except OSError as e:
                if e.errno == 11:
                    pass

    def connect(self, callback):
        self._datacallback = callback
        master, slave = pty.openpty()
        self._master = master
        self.subproc = subprocess.Popen(
            [self.executable], env=self.subenv,
            stdin=slave, stdout=slave,
            stderr=subprocess.PIPE)
        fcntl.fcntl(master, fcntl.F_SETFL, os.O_NONBLOCK)
        fcntl.fcntl(self.subproc.stderr.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
        self.readerthread = eventlet.spawn(self.relaydata)

    def write(self, data):
        self.subproc.stdin.write(data)

    def close(self):
        self.subproc.terminate()
        eventlet.sleep(10)
        self.subproc.kill()


class Plugin(object):
    def __init__(self, filename):
        self.filename = filename

    def create(self, nodes, element, configmanager, inputdata):
        if element != ['_console', 'session']:
            raise NotImplementedError("Shell plugins only do console")
        if len(nodes) != 1:
            raise NotImplementedError("_console/session is only single node")
        return ExecConsole(self.filename, nodes[0])
