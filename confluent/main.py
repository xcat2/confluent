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

# This is the main application.
# It should check for existing UDP socket to negotiate socket listen takeover
# It will have three paths into it:
#   -Unix domain socket
#   -TLS socket
#   -WSGI
# Additionally, it will be able to receive particular UDP packets to facilitate
# Things like heartbeating and discovery
# It also will optionally snoop SLP DA requests

import confluent.pluginapi as pluginapi
import confluent.httpapi as httpapi
import confluent.sockapi as sockapi
import eventlet
import eventlet.backdoor as backdoor
from eventlet.green import socket
from eventlet import wsgi
import multiprocessing
import sys
import os

def run():
    pluginapi.load_plugins()
    #TODO(jbjohnso): eventlet has a bug about unix domain sockets, this code 
    #works with bugs fixed
    #dbgsock = eventlet.listen("/var/run/confluent/dbg.sock",
    #                           family=socket.AF_UNIX)
    #eventlet.spawn_n(backdoor.backdoor_server, dbgsock)
    webservice = httpapi.HttpApi()
    webservice.start()
    sockservice = sockapi.SockApi()
    sockservice.start()
    while (1):
        eventlet.sleep(100)

