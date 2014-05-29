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
        self.subproc = None
        self._master = None
        self._datacallback = None
        self.readerthread = None
        self.executable = executable
        self.subenv = {
            'TERM': 'xterm',
            'CONFLUENT_NODE': node,
        }

    def relaydata(self):
        while self.subproc is not None:
            rdylist, _, _ = select.select(
                (self._master, self.subproc.stderr), (), (),
                3600 + (random.random() * 120))
            if self._master in rdylist:
                try:
                    somedata = os.read(self._master, 128)
                    while somedata:
                        self._datacallback(somedata)
                        eventlet.sleep(0)
                        somedata = os.read(self._master, 128)
                except OSError as e:
                    if e.errno != 11:
                        raise
            if self.subproc.stderr in rdylist:
                try:
                    somedata = self.subproc.stderr.read()
                    while somedata:
                        self._datacallback(somedata)
                        eventlet.sleep(0)
                        somedata = self.subproc.stderr.read()
                except IOError as e:
                    if e.errno != 11:
                        raise
            childstate = self.subproc.poll()
            if childstate is not None:
                self._datacallback(conapi.ConsoleEvent.Disconnect)
                self.subproc = None

    def connect(self, callback):
        self._datacallback = callback
        master, slave = pty.openpty()
        self._master = master
        self.subproc = subprocess.Popen(
            [self.executable], env=self.subenv,
            stdin=slave, stdout=slave,
            stderr=subprocess.PIPE, close_fds=True)
        os.close(slave)
        fcntl.fcntl(master, fcntl.F_SETFL, os.O_NONBLOCK)
        fcntl.fcntl(self.subproc.stderr.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
        self.readerthread = eventlet.spawn(self.relaydata)

    def write(self, data):
        os.write(self._master, data)

    def close(self):
        if self.subproc is None or self.subproc.poll() is not None:
            return
        self.subproc.terminate()
        waittime = 10
        while self.subproc is not None and self.subproc.poll() is None:
            eventlet.sleep(1)
            waittime -= 1
            if waittime == 0:
                break
        if self.subproc is not None and self.subproc.poll() is None:
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
