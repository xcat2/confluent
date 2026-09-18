#!/usr/bin/python3

# Copyright 2026 Lenovo
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
import asyncssh
import asyncssh.known_hosts as known_hosts
import confluent.tasks as tasks
import hashlib

_hashes = {'sha256': hashlib.sha256, 'sha384': hashlib.sha384, 'sha512': hashlib.sha512}

class _CancelSsh(Exception):
    pass

class _MyClient(asyncssh.SSHClient):
    def set_keyattrib(self, keyattrib):
        self.confluent_keyattrib = keyattrib

    def set_nodename(self, nodename):
        self.confluent_nodename = nodename

    def set_configmanager(self, configmanager):
        self.confluent_configmanager = configmanager

    def validate_host_ca_key(self, host, addr, port, key):
        kh = None
        with open('/etc/ssh/ssh_known_hosts', 'r') as skh:
            kh = known_hosts.import_known_hosts(skh.read())
        matchca = kh.match(host, addr, port)
        for ca in matchca[1]:
            if ca == key:
                return True
        return False

    def validate_host_public_key(self, host, addr, port, key):
        if hasattr(self, 'confluent_validate_hostkey'):
            if not self.confluent_validate_hostkey:
                return True
        if not hasattr(self, 'confluent_nodename') or not hasattr(self, 'confluent_configmanager'):
            return False
        cfg = self.confluent_configmanager
        nodename = self.confluent_nodename
        cfi = cfg.get_node_attributes(nodename, [self.confluent_keyattrib, 'pubkeys.addpolicy'])
        fprint = cfi.get(nodename, {}).get(self.confluent_keyattrib, {}).get('value', None)
        policy = cfi.get(nodename, {}).get('pubkeys.addpolicy', {}).get('value', 'tofu')

        if fprint:
            algo, expectedfingerprint = fprint.split('$', 1)
            if algo not in _hashes:
                return False
            keyfingerprint = _hashes[algo](key.public_data).hexdigest()
            if keyfingerprint == expectedfingerprint:
                return True
            return False  
        elif policy == 'tofu':
            keyfingerprint = hashlib.sha512(key.public_data).hexdigest()
            fprint = 'sha512$' + keyfingerprint
            tasks.spawn_task(cfg.set_node_attributes({nodename: {self.confluent_keyattrib: {'value': fprint}}}))
            return True
        return False

    def disable_host_key_validation(self):
        self.confluent_validate_hostkey = False

    def auth_banner_received(self, msg, lang):
        if hasattr(self, 'confluent_custom_ctx'):
            self.confluent_custom_ctx['banner'] = msg

    def password_auth_requested(self):
        if not hasattr(self, 'confluent_custom_ctx'):
            return None
        if self.confluent_custom_ctx.get('nologon'):
            raise _CancelSsh('nologon')
        if 'initialpassword' in self.confluent_custom_ctx:
            initpassword = self.confluent_custom_ctx.get('initialpassword')
            del self.confluent_custom_ctx['initialpassword']
            return initpassword
        elif 'password' in self.confluent_custom_ctx:
            password = self.confluent_custom_ctx.get('password')
            del self.confluent_custom_ctx['password']
            return password
        else:
            return None

    def password_change_requested(self, prompt, lang):
        print(repr(prompt))
        print(repr(lang))

    def password_change_failed(self):
        print("pcf")

    def password_changed(self):
        print("pc")

    def confluent_set_context(self, ctx):
        self.confluent_custom_ctx = ctx


def connect(target, context=None, disable_hostkey_validation=False, known_hosts=(), nodename=None, configmanager=None, keyattrib='pubkeys.ssh', quickquit=False, **kwargs):
    if context is None:
        context = {}
    def make_client():
        client = _MyClient()
        if disable_hostkey_validation:
            client.disable_host_key_validation()
        client.set_configmanager(configmanager)
        client.set_nodename(nodename)
        client.set_keyattrib(keyattrib) 

        client.confluent_set_context(context)
        return client
    login_timeout=30
    connect_timeout=30
    if quickquit:
        login_timeout=2
        connect_timeout=2
    sco = asyncssh.SSHClientConnectionOptions(
        client_factory=make_client,
        x509_trusted_cert_paths=None,
        known_hosts=known_hosts,
        login_timeout=login_timeout,
        connect_timeout=connect_timeout)
    return asyncssh.connect(target, options=sco, **kwargs)


async def get_ssh_banner(target):
    mycontext = {'nologon': True}
    try:
        async with connect(target, disable_hostkey_validation=True, quickquit=True, context=mycontext):
            pass
    except _CancelSsh:
        pass
    return mycontext.get('banner')


if __name__ == '__main__':
    import asyncio
    import sys
    asyncio.run(get_ssh_banner(sys.argv[1]))