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

import atexit
import confluent.auth as auth
import confluent.consoleserver as consoleserver
import confluent.core as confluentcore
import confluent.httpapi as httpapi
import confluent.log as log
import confluent.sockapi as sockapi
import eventlet
#import eventlet.backdoor as backdoor
import fcntl
#import multiprocessing
import sys
import os
import signal


def _daemonize():
    thispid = os.fork()
    if thispid > 0:
        os.waitpid(thispid, 0)
        os._exit(0)
    os.setsid()
    thispid = os.fork()
    if thispid > 0:
        print 'confluent server starting as pid %d' % thispid
        os._exit(0)
    os.closerange(0, 2)
    os.umask(63)
    os.open(os.devnull, os.O_RDWR)
    os.dup2(0, 1)
    os.dup2(0, 2)
    sys.stdout = log.Logger('stdout')
    sys.stderr = log.Logger('stderr')


def _updatepidfile():
    pidfile = open('/var/run/confluent/pid', 'w+')
    fcntl.flock(pidfile, fcntl.LOCK_EX)
    pidfile.write(str(os.getpid()))
    fcntl.flock(pidfile, fcntl.LOCK_UN)
    pidfile.close()


def _checkpidfile():
    try:
        pidfile = open('/var/run/confluent/pid', 'r+')
        fcntl.flock(pidfile, fcntl.LOCK_EX)
        pid = pidfile.read()
        if pid != '':
            print ('/var/run/confluent/pid exists and indicates %s is still '
                   'running' % pid)
            sys.exit(1)
        pidfile.write(str(os.getpid()))
        fcntl.flock(pidfile, fcntl.LOCK_UN)
        pidfile.close()
    except IOError:
        try:
            pidfile = open('/var/run/confluent/pid', 'w')
        except IOError as e:
            if e.errno != 2:
                raise
            os.makedirs('/var/run/confluent')
            pidfile = open('/var/run/confluent/pid', 'w')
        fcntl.flock(pidfile, fcntl.LOCK_EX)
        pidfile.write(str(os.getpid()))
        fcntl.flock(pidfile, fcntl.LOCK_UN)
        pidfile.close()
        pidfile = open('/var/run/confluent/pid', 'r')
        fcntl.flock(pidfile, fcntl.LOCK_SH)
        pid = pidfile.read()
        if pid != str(os.getpid()):
            print ('/var/run/confluent/pid exists and indicates %s is still '
                   'running' % pid)
            sys.exit(1)
        fcntl.flock(pidfile, fcntl.LOCK_UN)
        pidfile.close()


def terminate(signalname, frame):
    sys.exit(0)


def doexit():
    pidfile = open('/var/run/confluent/pid')
    pid = pidfile.read()
    if pid == str(os.getpid()):
        os.remove('/var/run/confluent/pid')


def run():
    _checkpidfile()
    confluentcore.load_plugins()
    _daemonize()
    _updatepidfile()
    auth.init_auth()
    signal.signal(signal.SIGINT, terminate)
    signal.signal(signal.SIGTERM, terminate)
    #TODO(jbjohnso): eventlet has a bug about unix domain sockets, this code
    #works with bugs fixed
    #dbgsock = eventlet.listen("/var/run/confluent/dbg.sock",
    #                           family=socket.AF_UNIX)
    #eventlet.spawn_n(backdoor.backdoor_server, dbgsock)
    consoleserver.start_console_sessions()
    webservice = httpapi.HttpApi()
    webservice.start()
    sockservice = sockapi.SockApi()
    sockservice.start()
    atexit.register(doexit)
    while 1:
        eventlet.sleep(100)
