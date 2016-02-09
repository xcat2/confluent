# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2016 Lenovo
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

# This module handles the task of multplexing console and any watchers.
# For example, 3 console windows may share a single http long poller
# It can additionally add watchers for certain messages
# messages.py will then check in for any watchers for the relevant resource
# and trigger notifications on watchers.
# This will allow a request to watch each individual nodes power state ond/or
# health results will async come
# over the watcher.  A client may only request to monitor a resource
# if it would normally be allowed to actually request it.  Tho monitoring
# continues, meaning any request, related or not, will send a notification
# to a watching client
# This enables, for example, for a web page to react on the fly to anyone
# noticing the health, power state, add, or delete of a node (any message
# suitably instrumented in messages.py).

# This is broken out so that messages and httpapi can both import it.
# This could be added to the socket api as well, but for now the focus shall
# be on httpapi to enable dynamic web behavior.

import confluent.util as util
import eventlet
import time

_multiplexers = {}
_cleanthread = None


def _assaign_multiplexid(multiplexer):
    sessid = util.randomstring(32)
    while sessid in _multiplexers:
        sessid = util.randomstring(32)
    _multiplexers[sessid] = {'multiplexer': multiplexer,
                               'expiry': time.time() + 60}
    return sessid


def _expire_multiplexers():
    global _cleanthread
    while multiplexers:
        currtime = time.time()
        for session in _multiplexers:
            if _multiplexers[session]['expiry'] < currtime:
                del _multiplexers[session]
    if multiplexers:
        _cleanthread = eventlet.spawn_after(15, _expire_multiplexers)
    else:
        _cleanthread = None


class Multiplexer(object):
    def __init__(self):
        _assign_multiplexid(self)


def handle_http(env, querydict):
    global _cleanthread
    if _cleanthread is None:
        _cleanthread = eventlet.spawn_after(60, _expire_multiplexers)
    if 'multiplexid' not in querydict or not querydict['multiplexid']:
        # This is a new request, create a new multiplexer
        multiplexer = Multiplexer()
    else:
        multiplexer = _multiplexers['multiplexid']['multiplexer']

