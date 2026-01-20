# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2022 Lenovo
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
import confluent.messages as msg
import confluent.netutil as netutil
import confluent.util as util
import confluent.config.configmanager as cfm
import os
import shutil
import tempfile
import socket
import yaml
import json

def mkdirp(path):
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno != 17:
            raise

def create_apikey():
    alpha = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./'
    newpass = ''.join([alpha[x >> 2] for x in bytearray(os.urandom(32))])
    return newpass


async def create_ident_image(node, configmanager):
    tmpd = tempfile.mkdtemp()
    ident = { 'nodename': node }
    apikey = create_apikey()
    configmanager.set_node_attributes({node: {'secret.selfapiarmtoken': apikey}})
    ident['apitoken'] = apikey
    # This particular mechanism does not (yet) do anything smart with collective
    # It would be a reasonable enhancement to list all collective server addresses
    # restricted by 'managercandidates'
    ident['deploy_servers'] = []
    ident['confluent_uuid'] = cfm.get_global('confluent_uuid')
    for myaddr in netutil.get_my_addresses():
        myaddr = socket.inet_ntop(myaddr[0], myaddr[1])
        ident['deploy_servers'].append(myaddr)
    ident['net_cfgs'] = netutil.get_flat_net_config(configmanager, node)
    with open(os.path.join(tmpd, 'cnflnt.yml'), 'w') as yamlout:
        yaml.safe_dump(ident, yamlout, default_flow_style=False)
    with open(os.path.join(tmpd, 'cnflnt.jsn'), 'w') as jsonout:
        json.dump(ident, jsonout)
    shutil.copytree('/var/lib/confluent/public/site/tls', os.path.join(tmpd, 'tls'))
    mkdirp('/var/lib/confluent/private/identity_files/')
    shutil.copy(os.path.join(tmpd, 'cnflnt.yml'), '/var/lib/confluent/private/identity_files/{0}.yml'.format(node))
    shutil.copy(os.path.join(tmpd, 'cnflnt.jsn'), '/var/lib/confluent/private/identity_files/{0}.json'.format(node))
    mkdirp('/var/lib/confluent/private/identity_images/')
    imgname = '/var/lib/confluent/private/identity_images/{0}.img'.format(node)
    if os.path.exists(imgname):
        os.remove(imgname)
    await util.check_call('/opt/confluent/bin/dir2img', tmpd, imgname, 'cnflnt_idnt')
    shutil.rmtree(tmpd)


async def update(nodes, element, configmanager, inputdata):
    for node in nodes:
        await create_ident_image(node, configmanager)
        yield msg.CreatedResource(
                'nodes/{0}/deployment/ident_image'.format(node))


