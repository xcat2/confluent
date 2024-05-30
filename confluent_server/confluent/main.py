# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
# Copyright 2015-2017 Lenovo
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


#import logging
#logging.basicConfig(filename='/tmp/asyn.log', level=logging.DEBUG)
import atexit
import confluent.auth as auth
import confluent.config.conf as conf
import confluent.config.configmanager as configmanager
try:
    import anydbm as dbm
except ModuleNotFoundError:
    import dbm
import confluent.consoleserver as consoleserver
import confluent.core as confluentcore
import confluent.httpapi as httpapi
import confluent.log as log
import confluent.collective.manager as collective
import confluent.discovery.protocols.pxe as pxe
import linecache
try:
    import confluent.sockapi as sockapi
except ImportError:
    #On platforms without pwd, give up on the sockapi in general and be http
    #only for now
    pass
import confluent.discovery.core as disco
import eventlet
dbgif = False
try:
    import eventlet.backdoor as backdoor
    dbgif = True
except Exception:
    pass
havefcntl = True
try:
    import fcntl
except ImportError:
    havefcntl = False
#import multiprocessing
import asyncio
import gc
from greenlet import greenlet
import sys
import os
import glob
import signal
import socket
import subprocess
import time
import traceback
import tempfile
import uuid


def format_stack(task):
    task.print_stack()
    extracted_list = []
    checked = set()
    for f in task.get_stack():
        lineno = f.f_lineno
        co = f.f_code
        filename = co.co_filename
        name = co.co_name
        if filename not in checked:
            checked.add(filename)
            linecache.checkcache(filename)
        line = linecache.getline(filename, lineno, f.f_globals)
        extracted_list.append((filename, lineno, name, line))

    exc = task._exception
    if not extracted_list:
        yield f'No stack for {task!r}'
    elif exc is not None:
        yield f'Traceback for {task!r} (most recent call last):'
    else:
        yield f'Stack for {task!r} (most recent call last):'

    for x in traceback.format_list(extracted_list):
        yield x
    if exc is not None:
        for line in traceback.format_exception_only(exc.__class__, exc):
            yield line


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
        print('confluent server starting as pid {0}'.format(thispid))
        os._exit(0)
    os.closerange(0, 2)
    os.open(os.devnull, os.O_RDWR)
    os.dup2(0, 1)
    os.dup2(0, 2)
    log.daemonized = True


def _redirectoutput():
    os.umask(63)
    sys.stdout = log.Logger('stdout', buffered=False)
    sys.stderr = log.Logger('stderr', buffered=False)


def _updatepidfile():
    pidfile = open('/var/run/confluent/pid', 'w+')
    fcntl.flock(pidfile, fcntl.LOCK_EX)
    pidfile.write(str(os.getpid()))
    fcntl.flock(pidfile, fcntl.LOCK_UN)
    pidfile.close()


def is_running():
    # Utility function for utilities to check if confluent is running
    try:
        pidfile = open('/var/run/confluent/pid', 'r+')
        fcntl.flock(pidfile, fcntl.LOCK_SH)
        pid = pidfile.read()
        if pid != '':
            try:
                os.kill(int(pid), 0)
                return pid
            except OSError:
                # There is no process running by that pid, must be stale
                pass
        fcntl.flock(pidfile, fcntl.LOCK_UN)
        pidfile.close()
    except IOError:
        pass
    return None


def _checkpidfile():
    try:
        pidfile = open('/var/run/confluent/pid', 'r+')
        fcntl.flock(pidfile, fcntl.LOCK_EX)
        pid = pidfile.read()
        if pid != '':
            try:
                os.kill(int(pid), 0)
                print ('/var/run/confluent/pid exists and indicates %s is still '
                       'running' % pid)
                sys.exit(1)
            except OSError:
                # There is no process running by that pid, must be stale
                pass
        pidfile.seek(0)
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
        ht.write('Thread trace: ({0})\n'.format(id(o)))
        ht.write(''.join(traceback.format_stack(o.gr_frame)))
    for atask in asyncio.all_tasks():
        ht.write('Async trace: ({0})\n'.format(id(atask)))
        ht.write(''.join([x for x in format_stack(atask)]))
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


def setlimits():
    try:
        import resource
        currlimit = resource.getrlimit(resource.RLIMIT_NOFILE)
        if currlimit[0] < currlimit[1]:
            resource.setrlimit(
                resource.RLIMIT_NOFILE, (currlimit[1], currlimit[1]))
    except Exception:
        pass

def assure_ownership(path):
    try:
        if os.getuid() != os.stat(path).st_uid:
            sys.stderr.write('{} is not owned by confluent user, change ownership\n'.format(path))
            sys.exit(1)
    except OSError as e:
        if e.errno == 13:
            sys.stderr.write('{} is not owned by confluent user, change ownership\n'.format(path))
            sys.exit(1)

def sanity_check():
    if os.getuid() == 0:
        return True
    assure_ownership('/etc/confluent')
    assure_ownership('/etc/confluent/cfg')
    for filename in glob.glob('/etc/confluent/cfg/*'):
        assure_ownership(filename)
    assure_ownership('/etc/confluent/privkey.pem')
    assure_ownership('/etc/confluent/srvcert.pem')


def migrate_db():
    tdir = tempfile.mkdtemp()
    subprocess.check_call(['python3', '-c', 'pass'])
    subprocess.check_call(['python2', '/opt/confluent/bin/confluentdbutil', 'dump', '-u', tdir])
    subprocess.check_call(['python3', '/opt/confluent/bin/confluentdbutil', 'restore', '-u', tdir])
    subprocess.check_call(['rm', '-rf', tdir])
    configmanager.init()


async def run(args):
    asyncio.get_event_loop().set_debug(True)
    setlimits()
    try:
        configmanager.ConfigManager(None)
    except dbm.error:
        migrate_db()
    try:
        signal.signal(signal.SIGUSR1, dumptrace)
    except AttributeError:
        pass   # silly windows
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
    sanity_check()
    try:
        confluentcore.load_plugins()
    except:
        doexit()
        raise
    try:
        log.log({'info': 'Confluent management service starting'}, flush=True)
    except (OSError, IOError) as e:
        print(repr(e))
        sys.exit(1)
    if '-f' not in args:
        _daemonize()
    if '-o' not in args:
        _redirectoutput()
    if havefcntl:
        _updatepidfile()
    signal.signal(signal.SIGINT, terminate)
    signal.signal(signal.SIGTERM, terminate)
    atexit.register(doexit)
    confluentuuid = configmanager.get_global('confluent_uuid')
    if not confluentuuid:
        confluentuuid = str(uuid.uuid4())
        configmanager.set_global('confluent_uuid', confluentuuid)
    if not configmanager._masterkey:
        configmanager.init_masterkey()
    if dbgif:
        oumask = os.umask(0o077)
        try:
            os.remove('/var/run/confluent/dbg.sock')
        except OSError:
            pass  # We are not expecting the file to exist
        try:
            dbgsock = eventlet.listen("/var/run/confluent/dbg.sock",
                                       family=socket.AF_UNIX)
            eventlet.spawn_n(backdoor.backdoor_server, dbgsock)
        except AttributeError:
            pass  # Windows...
        os.umask(oumask)
    auth.check_for_yaml()
    collective.startup()
    await consoleserver.initialize()
    http_bind_host, http_bind_port = _get_connector_config('http')
    sock_bind_host, sock_bind_port = _get_connector_config('socket')
    try:
        sockservice = sockapi.SockApi(sock_bind_host, sock_bind_port)
        asyncio.get_event_loop().create_task(sockservice.start())
    except NameError:
        pass
    webservice = httpapi.HttpApi(http_bind_host, http_bind_port)
    webservice.start()
    while len(list(configmanager.list_collective())) >= 2:
        # If in a collective, stall automatic startup activity
        # until we establish quorum
        try:
            configmanager.check_quorum()
            break
        except Exception:
            await asyncio.sleep(0.5)
    eventlet.spawn_n(disco.start_detection)
    await asyncio.sleep(1)
    await consoleserver.start_console_sessions()
    while 1:
        await asyncio.sleep(100)

def _get_connector_config(session):
    host = conf.get_option(session, 'bindhost')
    port = conf.get_int_option(session, 'bindport')
    return (host, port)
