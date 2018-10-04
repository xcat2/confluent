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
import eventlet
import hashlib
import sys
sys.modules['gssapi'] = None
paramiko = eventlet.import_patched('paramiko')


class HostKeyHandler(paramiko.client.MissingHostKeyPolicy):

    def __init__(self, configmanager, node):
        self.cfm = configmanager
        self.node = node

    def missing_host_key(self, client, hostname, key):
        fingerprint = 'sha512$' + hashlib.sha512(key.asbytes()).hexdigest()
        cfg = self.cfm.get_node_attributes(
                self.node, ('pubkeys.ssh', 'pubkeys.addpolicy'))
        if 'pubkeys.ssh' not in cfg[self.node]:
            if ('pubkeys.addpolicy' in cfg[self.node] and
                    cfg[self.node]['pubkeys.addpolicy'] and
                    cfg[self.node]['pubkeys.addpolicy']['value'] == 'manual'):
                raise cexc.PubkeyInvalid('New ssh key detected',
                                         key.asbytes(), fingerprint,
                                         'pubkeys.ssh', 'newkey')
            auditlog = log.Logger('audit')
            auditlog.log({'node': self.node, 'event': 'sshautoadd',
                          'fingerprint': fingerprint})
            self.cfm.set_node_attributes(
                    {self.node: {'pubkeys.ssh': fingerprint}})
            return True
        elif cfg[self.node]['pubkeys.ssh']['value'] == fingerprint:
            return True
        raise cexc.PubkeyInvalid(
            'Mismatched SSH host key detected', key.asbytes(), fingerprint,
                'pubkeys.ssh', 'mismatch'
        )


class SshShell(conapi.Console):

    def __init__(self, node, config, username='', password=''):
        self.node = node
        self.ssh = None
        self.datacallback = None
        self.nodeconfig = config
        self.username = username
        self.password = password
        self.inputmode = 0  # 0 = username, 1 = password...

    def recvdata(self):
        while self.connected:
            pendingdata = self.shell.recv(8192)
            if pendingdata == '':
                self.datacallback(conapi.ConsoleEvent.Disconnect)
                return
            self.datacallback(pendingdata)

    def connect(self, callback):
        # for now, we just use the nodename as the presumptive ssh destination
        # TODO(jjohnson2): use a 'nodeipget' utility function for architectures
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
        self.ssh.set_missing_host_key_policy(
                HostKeyHandler(self.nodeconfig, self.node))
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
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            self.datacallback(str(e))
            self.inputmode = 0
            self.username = ''
            self.password = ''
            self.datacallback('\r\nlogin as: ')
            return
        except cexc.PubkeyInvalid as pi:
            self.keyaction = ''
            self.candidatefprint = pi.fingerprint
            self.datacallback(pi.message)
            self.keyattrname = pi.attrname
            self.datacallback('\r\nNew fingerprint: ' + pi.fingerprint)
            self.inputmode = -1
            self.datacallback('\r\nEnter "disconnect" or "accept": ')
            return
        self.inputmode = 2
        self.connected = True
        self.shell = self.ssh.invoke_shell()
        self.rxthread = eventlet.spawn(self.recvdata)

    def write(self, data):
        if self.inputmode == -1:
            while len(data) and data[0] == b'\x7f' and len(self.keyaction):
                self.datacallback('\b \b')  # erase previously echoed value
                self.keyaction = self.keyaction[:-1]
                data = data[1:]
            while len(data) and data[0] == b'\x7f':
                data = data[1:]
            while b'\x7f' in data:
                delidx = data.index(b'\x7f')
                data = data[:delidx - 1] + data[delidx + 1:]
            self.keyaction += data
            if '\r' in self.keyaction:
                action = self.keyaction.split('\r')[0]
                if action.lower() == 'accept':
                    self.nodeconfig.set_node_attributes(
                        {self.node:
                             {self.keyattrname: self.candidatefprint}})
                    self.datacallback('\r\n')
                    self.logon()
                elif action.lower() == 'disconnect':
                    self.datacallback(conapi.ConsoleEvent.Disconnect)
                else:
                    self.keyaction = ''
                    self.datacallback('\r\nEnter "disconnect" or "accept": ')
            elif len(data) > 0:
                self.datacallback(data)
        elif self.inputmode == 0:
            while len(data) and data[0] == b'\x7f' and len(self.username):
                self.datacallback('\b \b')  # erase previously echoed value
                self.username = self.username[:-1]
                data = data[1:]
            while len(data) and data[0] == b'\x7f':
                data = data[1:]
            while b'\x7f' in data:
                delidx = data.index(b'\x7f')
                data = data[:delidx - 1] + data[delidx + 1:]
            self.username += data
            if '\r' in self.username:
                self.username, self.password = self.username.split('\r')[:2]
                lastdata = data.split('\r')[0]
                if lastdata != '':
                    self.datacallback(lastdata)
                self.datacallback('\r\nEnter password: ')
                self.inputmode = 1
            elif len(data) > 0:
                # echo back typed data
                self.datacallback(data)
        elif self.inputmode == 1:
            while len(data) > 0 and data[0] == b'\x7f':
                self.password = self.password[:-1]
                data = data[1:]
            while b'\x7f' in data:
                delidx = data.index(b'\x7f')
                data = data[:delidx - 1] + data[delidx + 1:]
            self.password += data
            if '\r' in self.password:
                self.password = self.password.split('\r')[0]
                self.datacallback('\r\n')
                self.logon()
        else:
            self.shell.sendall(data)

    def close(self):
        if self.ssh is not None:
            self.ssh.close()
        self.datacallback = None

def create(nodes, element, configmanager, inputdata):
    if len(nodes) == 1:
        return SshShell(nodes[0], configmanager)