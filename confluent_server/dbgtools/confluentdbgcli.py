#!/usr/bin/python3
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2017 Lenovo
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


# Note that this script has a high chance of breaking confluent, so
# do not be surprised if confluent crashes as you exit...

import atexit
import os
import select
import socket
import readline
import sys
import threading

historypath = os.path.expanduser("~/.confluentdbghistory")

def save_history():
    import readline
    try:
        readline.write_history_file(historypath)
    except:
        pass

if os.path.exists(historypath):
    readline.set_history_length(1000)
    readline.read_history_file(historypath)

atexit.register(save_history)
readline.parse_and_bind('tab: complete')
conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
conn.connect('/var/run/confluent/dbg.sock')

pendingoutput = None

class GetInput(threading.Thread):
    def run(self):
        global pendingoutput
        while True:
            try:
                 pendingoutput = input('')
            except EOFError:
                 pendingoutput = False
                 break


inputthread = GetInput()
inputthread.start()
while True:
    try:
        r, _, _ = select.select((conn,), (), (), 0.1)
    except select.error:
        continue
    if conn in r:
        sys.stdout.write(conn.recv(1).decode('utf8'))
    if pendingoutput is not None:
        if pendingoutput is False:
            conn.shutdown(socket.SHUT_WR)
            sys.exit(1)
        else:
            conn.sendall((pendingoutput + '\n').encode('utf8'))
        pendingoutput = None
    sys.stdout.flush()
