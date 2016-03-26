# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
# Copyright 2015 Lenovo
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
import confluent.config.conf as conf
import confluent.config.configmanager as configmanager
import confluent.consoleserver as consoleserver
import confluent.core as confluentcore
import confluent.httpapi as httpapi
import confluent.log as log
try:
    import confluent.sockapi as sockapi
except ImportError:
    #On platforms without pwd, give up on the sockapi in general and be http
    #only for now
    pass
import eventlet
dbgif = False
if  map(int, (eventlet.__version__.split('.'))) > [0, 18]:
    import eventlet.backdoor as backdoor
    dbgif = True
havefcntl = True
try:
    import fcntl
except ImportError:
    havefcntl = False
#import multiprocessing
import gc
from greenlet import greenlet
import sys
import os
import signal
import socket
import time
import traceback


def _daemonize():
    if not 'fork' in os.__dict__:
        return
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

def dumptrace(signalname, frame):
    ht = open('/var/log/confluent/hangtraces', 'a')
    ht.write('Dumping active trace on ' + time.strftime('%X %x\n'))
    ht.write(''.join(traceback.format_stack(frame)))
    for o in gc.get_objects():
        if not isinstance(o, greenlet):
            continue
        if not o:
            continue
        ht.write('Thread trace:\n')
        ht.write(''.join(traceback.format_stack(o.gr_frame)))
    ht.close()

def doexit():
    if not havefcntl:
        return
    try:
        os.remove('/var/run/confluent/dbg.sock')
    except OSError:
        pass
    pidfile = open('/var/run/confluent/pid')
    pid = pidfile.read()
    if pid == str(os.getpid()):
        os.remove('/var/run/confluent/pid')


def _initsecurity(config):
    if config.has_option('security', 'externalcfgkey'):
        keyfile = config.get('security', 'externalcfgkey')
        with open(keyfile, 'r') as keyhandle:
            key = keyhandle.read()
        configmanager.init_masterkey(key)
        # We don't want to os._exit() until sync finishes from
        # init above
        configmanager.ConfigManager.wait_for_sync()


def run():
    signal.signal(signal.SIGUSR1, dumptrace)
    if havefcntl:
        _checkpidfile()
    conf.init_config()
    try:
        config = conf.get_config()
        _initsecurity(config)
    except:
        sys.stderr.write("Error unlocking credential store\n")
        doexit()
        sys.exit(1)
    try:
        confluentcore.load_plugins()
    except:
        doexit()
        raise
    _daemonize()
    if havefcntl:
        _updatepidfile()
    auth.init_auth()
    signal.signal(signal.SIGINT, terminate)
    signal.signal(signal.SIGTERM, terminate)
    #TODO(jbjohnso): eventlet has a bug about unix domain sockets, this code
    #works with bugs fixed
    if dbgif:
        oumask = os.umask(0077)
        dbgsock = eventlet.listen("/var/run/confluent/dbg.sock",
                                   family=socket.AF_UNIX)
        eventlet.spawn_n(backdoor.backdoor_server, dbgsock)
        os.umask(oumask)
    http_bind_host, http_bind_port = _get_connector_config('http')
    sock_bind_host, sock_bind_port = _get_connector_config('socket')
    consoleserver.start_console_sessions()
    webservice = httpapi.HttpApi(http_bind_host, http_bind_port)
    webservice.start()
    try:
        sockservice = sockapi.SockApi(sock_bind_host, sock_bind_port)
        sockservice.start()
    except NameError:
        pass
    atexit.register(doexit)
    while 1:
        eventlet.sleep(100)

def _get_connector_config(session):
    host = conf.get_option(session, 'bindhost')
    port = conf.get_int_option(session, 'bindport')
    return (host, port)
