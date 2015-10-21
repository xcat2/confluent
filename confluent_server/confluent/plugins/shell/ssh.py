# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2015 Lenovo
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

__author__ = 'jjohnson2'

# This plugin provides an ssh implementation comforming to the 'console'
# specification.  consoleserver or shellserver would be equally likely
# to use this.

import confluent.interface.console as conapi
import eventlet
paramiko = eventlet.import_patched('paramiko')


class SshShell(conapi.Console):

    def __init__(self, node, config, username='', password=''):
        self.node = node
        self.nodeconfig = config
        self.username = username
        self.password = password
        self.inputmode = 0 # 0 = username, 1 = password...

    def recvdata(self):
        while self.connected:
            pendingdata = self.shell.recv(8192)
            if pendingdata == '':
                self.datacallback(conapi.ConsoleEvent.Disconnect)
                return
            self.datacallback(pendingdata)

    def connect(self, callback):
        # for now, we just use the nodename as the presumptive ssh destination
        #TODO(jjohnson2): use a 'nodeipget' utility function for architectures
        # that would rather not use the nodename as anything but an opaque
        # identifier
        self.datacallback = callback
        if self.username is not '':
            self.logon()
        else:
            self.inputmode = 0
            callback('\r\nlogin as: ')
        return

    def logon(self):
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
        try:
            self.ssh.connect(self.node, username=self.username,
                             password=self.password, allow_agent=False,
                             look_for_keys=False)
        except paramiko.AuthenticationException:
            self.inputmode = 0
            self.username = ''
            self.password = ''
            self.datacallback('\r\nlogin as: ')
            return
        self.inputmode = 2
        self.connected = True
        self.shell = self.ssh.invoke_shell()
        self.rxthread = eventlet.spawn(self.recvdata)

    def write(self, data):
        if self.inputmode == 0:
            self.username += data
            if '\r' in self.username:
                self.username, self.password = self.username.split('\r')
                lastdata = data.split('\r')[0]
                if lastdata != '':
                    self.datacallback(lastdata)
                self.datacallback('\r\nEnter password: ')
                self.inputmode = 1
            else:
                # echo back typed data
                self.datacallback(data)
        elif self.inputmode == 1:
            self.password += data
            if '\r' in self.password:
                self.password = self.password.split('\r')[0]
                self.datacallback('\r\n')
                self.logon()
        else:
            self.shell.sendall(data)

    def close(self):
        self.ssh.close()

def create(nodes, element, configmanager, inputdata):
    if len(nodes) == 1:
        return SshShell(nodes[0], configmanager)