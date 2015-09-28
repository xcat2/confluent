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


#This defines config variable to store the global configuration for confluent
import ConfigParser
import os

_config = None

def init_config():
    global _config
    configfile = "/etc/confluent/service.cfg"
    if os.name == 'nt':
        configfile = os.path.join(os.getentv('SystemDrive'), '\\ProgramData',
                                  'confluent', 'cfg', 'service.cfg')
    _config = ConfigParser.ConfigParser()
    _config.read(configfile)

def get_config():
    return _config

def get_int_option(section, option):
    try:
        return _config.getint(section, option)
    except (
    ConfigParser.NoSectionError, ConfigParser.NoOptionError, ValueError):
        return None

def get_boolean_option(section, option):
    try:
        return _config.getboolean(section, option)
    except (
    ConfigParser.NoSectionError, ConfigParser.NoOptionError, ValueError):
        return None

def get_option(section, option):
    try:
        return _config.get(section, option)
    except (ConfigParser.NoSectionError, ConfigParser.NoOptionError):
        return None
