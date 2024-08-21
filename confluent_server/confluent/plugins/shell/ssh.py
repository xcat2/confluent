# vim: tabstop=4 shiftwidth=4 softtabstop=4

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


# This plugin provides an ssh implementation comforming to the 'console'
# specification.  consoleserver or shellserver would be equally likely
# to use this.

import confluent.exceptions as cexc
import confluent.interface.console as conapi
import confluent.log as log
import confluent.tasks as tasks
import confluent.util as util

import hashlib
import sys
sys.modules['gssapi'] = None
import asyncio
import asyncssh



class SshShell(conapi.Console):

    def __init__(self, node, config, username=b'', password=b''):
        self.node = node
        self.ssh = None
        self.datacallback = None
        self.nodeconfig = config
        self.username = username
        self.password = password
        self.connected = False
        self.width = 80
        self.height = 24
        self.inputmode = 0  # 0 = username, 1 = password...

    def resize(self, width, height):
        self.width = width
        self.height = height
        if not self.connected:
            return
        self.shell[0].channel.change_terminal_size(width=width, height=height)

    async def recvdata(self):
        while self.connected:
            pendingdata = await self.shell[1].read(8192)
            if not pendingdata:
                self.ssh.close()
                if self.datacallback:
                    await self.datacallback(conapi.ConsoleEvent.Disconnect)
                return
            await self.datacallback(pendingdata)

    async def connect(self, callback):
        # for now, we just use the nodename as the presumptive ssh destination
        # TODO(jjohnson2): use a 'nodeipget' utility function for architectures
        # that would rather not use the nodename as anything but an opaque
        # identifier
        self.datacallback = callback
        if self.username != b'':
            self.logon()
        else:
            self.inputmode = 0
            await callback('\r\nlogin as: ')
        return

    def logon(self):
        self.inputmode = -3
        tasks.spawn(self.do_logon())
    
    async def do_logon(self):
        sco = asyncssh.SSHClientConnectionOptions()
        #The below would be to support the confluent db, and only fallback if the SSH CA do not work
        # have to catch the valueerror and use ssh-keyscan to trigger this, asyncssh host key handling
        # is a bit more limited compared to paramiko

        #but... leverage /etc/ssh/ssh_known_hosts, we can try that way, and if it fails, fallback to our
        #confluent db based handler
        #sco.client_fatory = SSHKnownHostsLookup
        try:
            await self.datacallback('\r\nConnecting to {}...'.format(self.node))
            try:
                self.ssh = await asyncssh.connect(self.node, username=self.username.decode(), password=self.password.decode(), known_hosts='/etc/ssh/ssh_known_hosts')
            except ValueError:
                #TODO: non-cert ssh targets
                raise
        except cexc.PubkeyInvalid as pi:
            self.ssh.close()
            self.keyaction = b''
            self.candidatefprint = pi.fingerprint
            await self.datacallback(pi.message)
            self.keyattrname = pi.attrname
            await self.datacallback('\r\nNew fingerprint: ' + pi.fingerprint)
            self.inputmode = -1
            await self.datacallback('\r\nEnter "disconnect" or "accept": ')
            return
        except Exception as e:
            if self.ssh:
                self.ssh.close()
            self.inputmode = 0
            self.username = b''
            self.password = b''
            warn = 'Error connecting to {0}:\r\n {1}\r\n'.format(self.node, str(e))
            await self.datacallback('\r\n' + warn)
            await self.datacallback('\r\nlogin as: ')
            return
        self.inputmode = 2
        self.connected = True
        await self.datacallback('Connected\r\n')
        self.shell = await self.ssh.open_session(term_type='vt100', term_size=(self.width, self.height))
        self.rxthread = tasks.spawn_task(self.recvdata())

    async def write(self, data):
        if self.inputmode == -2:
            await self.datacallback(conapi.ConsoleEvent.Disconnect)
            return
        elif self.inputmode == -3:
            return
        elif self.inputmode == -1:
            while len(data) and data[0:1] == b'\x7f' and len(self.keyaction):
                await self.datacallback('\b \b')  # erase previously echoed value
                self.keyaction = self.keyaction[:-1]
                data = data[1:]
            while len(data) and data[0:1] == b'\x7f':
                data = data[1:]
            while b'\x7f' in data:
                delidx = data.index(b'\x7f')
                data = data[:delidx - 1] + data[delidx + 1:]
            self.keyaction += data
            if b'\r' in self.keyaction:
                action = self.keyaction.split(b'\r')[0]
                if action.lower() == b'accept':
                    self.nodeconfig.set_node_attributes(
                        {self.node:
                             {self.keyattrname: self.candidatefprint}})
                    await self.datacallback('\r\n')
                    self.logon()
                elif action.lower() == b'disconnect':
                    await self.datacallback(conapi.ConsoleEvent.Disconnect)
                else:
                    self.keyaction = b''
                    await self.datacallback('\r\nEnter "disconnect" or "accept": ')
            elif len(data) > 0:
                self.datacallback(data)
        elif self.inputmode == 0:
            while len(data) and data[0:1] == b'\x7f' and len(self.username):
                self.datacallback('\b \b')  # erase previously echoed value
                self.username = self.username[:-1]
                data = data[1:]
            while len(data) and data[0:1] == b'\x7f':
                data = data[1:]
            while b'\x7f' in data:
                delidx = data.index(b'\x7f')
                data = data[:delidx - 1] + data[delidx + 1:]
            self.username += data
            if b'\r' in self.username:
                self.username, self.password = self.username.split(b'\r')[:2]
                lastdata = data.split(b'\r')[0]
                if lastdata != '':
                    await self.datacallback(lastdata)
                await self.datacallback('\r\nEnter password: ')
                self.inputmode = 1
            elif len(data) > 0:
                # echo back typed data
                await self.datacallback(data)
        elif self.inputmode == 1:
            while len(data) > 0 and data[0:1] == b'\x7f':
                self.password = self.password[:-1]
                data = data[1:]
            while b'\x7f' in data:
                delidx = data.index(b'\x7f')
                data = data[:delidx - 1] + data[delidx + 1:]
            self.password += data
            if b'\r' in self.password:
                self.password = self.password.split(b'\r')[0]
                await self.datacallback(b'\r\n')
                self.logon()
        else:
            self.shell[0].write(data.decode())

    async def close(self):
        if self.ssh is not None:
            self.ssh.close()
        self.datacallback = None

async def create(nodes, element, configmanager, inputdata):
    if len(nodes) == 1:
        yield SshShell(nodes[0], configmanager)
