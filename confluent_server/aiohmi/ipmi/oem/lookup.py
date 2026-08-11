# Copyright 2015 Lenovo Corporation
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

import logging
import os
import sys

import aiohmi.ipmi.oem.generic as generic
import aiohmi.ipmi.oem.lenovo.handler as lenovo


logger = logging.getLogger(__name__)

# The mapping comes from
# http://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
# Only mapping the ones with known backends
oemmap = {
    20301: lenovo,  # IBM x86 (and System X at Lenovo)
    19046: lenovo,  # Lenovo x86 (e.g. Thinkserver)
    7154: lenovo,
}


async def get_oem_handler(oemid, ipmicmd, *args):
    # first try to find with composite key manufacturer_id.product_id,
    # if found return directly
    # then try to find with manufacturer_id
    for item in (
        '{}.{}'.format(oemid['manufacturer_id'], oemid['product_id']),
        oemid['manufacturer_id'],
    ):
        if item in oemmap:
            return (await oemmap[item].OEMHandler.create(oemid, ipmicmd, *args), True)
    return await generic.OEMHandler.create(oemid, ipmicmd, *args), False


def load_plugins():
    # load plugins and register oemmap
    path = os.path.dirname(os.path.realpath(__file__))

    for plugindir in os.listdir(path):
        plugindir = os.path.join(path, plugindir)

        if not os.path.isdir(plugindir):
            continue
        sys.path.insert(1, plugindir)
        # two passes, to avoid adding both py and pyc files
        find_plugin(path, plugindir)
        # restore path to not include the plugindir
        sys.path.pop(1)


def find_plugin(base_dir, cur_dir):
    # scan to process items in the dir
    # if is a directory, go into the directory to find plugins
    # if is handler.py try to load and find the key to register
    # else skip
    for item in os.listdir(cur_dir):
        abs_path = os.path.join(cur_dir, item)
        if os.path.isdir(abs_path):
            find_plugin(base_dir, abs_path)
        elif item == 'handler.py':
            load_and_register(base_dir, cur_dir)
        else:
            pass


def load_and_register(base_dir, cur_dir):
    try:
        oem_handler = __import__(make_plugin_name(base_dir, cur_dir),
                                 fromlist=['handler'])
        if 'device_type_supported' in oem_handler.__dict__:
            for type in oem_handler.device_type_supported:
                register_oem_map(type, oem_handler)
        else:
            logger.debug(
                'handler in {} does not support plugin.'.format(cur_dir))
    except Exception as ex:
        logger.exception('exception while loading handler in {} : {}'
                         .format(cur_dir, ex))


def register_oem_map(type, handler):
    if type in oemmap:
        logger.info('type {} already registered as {}, replaced with {}.'
                    .format(type, oemmap.get(type), handler))
        oemmap[type] = handler
    else:
        oemmap[type] = handler


def make_plugin_name(base_dir, cur_dir):
    return '{}.{}.{}'.format(__package__,
                             os.path.relpath(cur_dir, base_dir)
                             .replace('/', '.'),
                             'handler')


# load_plugins
load_plugins()
