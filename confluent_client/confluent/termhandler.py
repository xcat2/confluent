__author__ = 'jbjohnso'

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 Lenovo Corporation
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

#This file is responsible for a client-side communication method to enable
#capabilities like measuring and rearranging the terminal window for
#wcons

import atexit
import os
import socket
import stat
import threading

class TermHandler(object):
    def __init__(self, path):
        self.path = path
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            os.remove(path)
        except OSError:  # if file does not exist, no big deal
            pass
        atexit.register(self.shutdown)
        self.socket.bind(path)
        os.chmod(path, stat.S_IWUSR | stat.S_IRUSR)
        th = threading.Thread(target=self.sockinteract)
        th.daemon = True
        th.start()

    def shutdown(self):
        try:
            os.remove(self.path)
        except OSError:
            pass

    def sockinteract(self):
        self.socket.listen(5)
        while True:
            connection = None
            try:
                connection, address = self.socket.accept()
                connection.sendall(b"confetty control v1--\n")
                cmd = connection.recv(8)
                if b'GETWINID' == cmd:
                    winid = os.environ['WINDOWID']
                    if not isinstance(winid, bytes):
                        winid = winid.encode('utf8')
                    connection.sendall(winid)
                connection.close()
            except BaseException:
                pass
            finally:
                if connection is not None:
                    connection.close()
