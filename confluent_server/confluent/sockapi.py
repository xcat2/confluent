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
# ALl rights reserved

# This is the socket api layer.
# It implement unix and tls sockets
#

import atexit
import errno
import os
import pwd
import stat
import struct
import sys
import traceback

import eventlet.green.socket as socket
import eventlet.green.ssl as ssl
import eventlet

import confluent.auth as auth
import confluent.tlvdata as tlvdata
import confluent.consoleserver as consoleserver
import confluent.config.configmanager as configmanager
import confluent.exceptions as exc
import confluent.log as log
import confluent.core as pluginapi
import confluent.shellserver as shellserver


tracelog = None
auditlog = None
try:
    SO_PEERCRED = socket.SO_PEERCRED
except AttributeError:
    import platform
    if "ppc64" in platform.machine():
        SO_PEERCRED = 21
    else:
        SO_PEERCRED = 17


class ClientConsole(object):
    def __init__(self, client):
        self.client = client
        self.xmit = False
        self.pendingdata = []

    def sendall(self, data):
        if not self.xmit:
            self.pendingdata.append(data)
            return
        send_data(self.client, data)

    def startsending(self):
        self.xmit = True
        for datum in self.pendingdata:
            send_data(self.client, datum)
        self.pendingdata = None


def send_data(connection, data):
    try:
        tlvdata.send(connection, data)
    except IOError as ie:
        if ie.errno != errno.EPIPE:
            raise


def sessionhdl(connection, authname, skipauth=False):
    # For now, trying to test the console stuff, so let's just do n4.
    authenticated = False
    authdata = None
    cfm = None
    if skipauth:
        authenticated = True
        cfm = configmanager.ConfigManager(tenant=None, username=authname)
    elif authname:
        authdata = auth.authorize(authname, element=None)
        if authdata is not None:
            cfm = authdata[1]
            authenticated = True
    send_data(connection, "Confluent -- v0 --")
    while not authenticated:  # prompt for name and passphrase
        send_data(connection, {'authpassed': 0})
        response = tlvdata.recv(connection)
        authname = response['username']
        passphrase = response['password']
        # note(jbjohnso): here, we need to authenticate, but not
        # authorize a user.  When authorization starts understanding
        # element path, that authorization will need to be called
        # per request the user makes
        authdata = auth.check_user_passphrase(authname, passphrase)
        if authdata is None:
            auditlog.log(
                {'operation': 'connect', 'user': authname, 'allowed': False})
        else:
            authenticated = True
            cfm = authdata[1]
    send_data(connection, {'authpassed': 1})
    request = tlvdata.recv(connection)
    while request is not None:
        try:
            process_request(
                connection, request, cfm, authdata, authname, skipauth)
        except exc.ConfluentException as e:
            if ((not isinstance(e, exc.LockedCredentials)) and
                    e.apierrorcode == 500):
                tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                         event=log.Events.stacktrace)
            send_data(connection, {'errorcode': e.apierrorcode,
                                   'error': e.apierrorstr,
                                   'detail': e.get_error_body()})
            send_data(connection, {'_requestdone': 1})
        except SystemExit:
            sys.exit(0)
        except:
            tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                         event=log.Events.stacktrace)
            send_data(connection, {'errorcode': 500,
                                      'error': 'Unexpected error'})
            send_data(connection, {'_requestdone': 1})
        request = tlvdata.recv(connection)


def send_response(responses, connection):
    if responses is None:
        return
    for rsp in responses:
        send_data(connection, rsp.raw())
    send_data(connection, {'_requestdone': 1})


def process_request(connection, request, cfm, authdata, authname, skipauth):
    if not isinstance(request, dict):
        raise exc.InvalidArgumentException
    operation = request['operation']
    path = request['path']
    params = request.get('parameters', {})
    hdlr = None
    if not skipauth:
        authdata = auth.authorize(authdata[2], path, authdata[3], operation)
        auditmsg = {
            'operation': operation,
            'target': path,
        }
        if authdata is None:
            auditmsg['allowed'] = False
            auditlog.log(auditmsg)
            raise exc.ForbiddenRequest()
        auditmsg['user'] = authdata[2]
        if authdata[3] is not None:
            auditmsg['tenant'] = authdata[3]
        auditmsg['allowed'] = True
        auditlog.log(auditmsg)
    try:
        if operation == 'start':
            return start_term(authname, cfm, connection, params, path,
                              authdata, skipauth)
        elif operation == 'shutdown':
            configmanager.ConfigManager.shutdown()
        else:
            hdlr = pluginapi.handle_path(path, operation, cfm, params)
    except exc.NotFoundException as e:
        send_data(connection, {"errorcode": 404,
                                  "error": "Target not found - " + str(e)})
        send_data(connection, {"_requestdone": 1})
    except exc.InvalidArgumentException as e:
        send_data(connection, {"errorcode": 400,
                                  "error": "Bad Request - " + str(e)})
        send_data(connection, {"_requestdone": 1})
    send_response(hdlr, connection)
    return


def start_term(authname, cfm, connection, params, path, authdata, skipauth):
    elems = path.split('/')
    if len(elems) < 4 or elems[1] != 'nodes':
        raise exc.InvalidArgumentException('Invalid path {0}'.format(path))
    node = elems[2]
    ccons = ClientConsole(connection)
    skipreplay = False
    if params and 'skipreplay' in params and params['skipreplay']:
        skipreplay = True
    if elems[3] == "console":
        consession = consoleserver.ConsoleSession(
            node=node, configmanager=cfm, username=authname,
            datacallback=ccons.sendall, skipreplay=skipreplay)
    elif len(elems) >= 6 and elems[3:5] == ['shell', 'sessions']:
        if len(elems) == 7:
            sessionid = elems[5]
        else:
            sessionid = None
        consession = shellserver.ShellSession(
            node=node, configmanager=cfm, username=authname,
            datacallback=ccons.sendall, skipreplay=skipreplay,
            sessionid=sessionid)

    else:
        raise exc.InvalidArgumentException('Invalid path {0}'.format(path))

    if consession is None:
        raise Exception("TODO")
    send_data(connection, {'started': 1})
    ccons.startsending()
    bufferage = consession.get_buffer_age()
    if bufferage is not False:
        send_data(connection, {'bufferage': bufferage})
    while consession is not None:
        data = tlvdata.recv(connection)
        if type(data) == dict:
            if data['operation'] == 'stop':
                consession.destroy()
                return
            elif data['operation'] == 'break':
                consession.send_break()
                continue
            elif data['operation'] == 'reopen':
                consession.reopen()
                continue
            else:
                process_request(connection, data, cfm, authdata, authname,
                                skipauth)
                continue
        if not data:
            consession.destroy()
            return
        consession.write(data)


def _tlshandler(bind_host, bind_port):
    plainsocket = socket.socket(socket.AF_INET6)
    plainsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    plainsocket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    bound = False
    while not bound:
        try:
            plainsocket.bind((bind_host, bind_port, 0, 0))
            bound = True
        except socket.error as e:
            if e.errno != 98:
                raise
            sys.stderr.write('TLS Socket in use, retrying in 1 second\n')
            eventlet.sleep(1)
    plainsocket.listen(5)
    while (1):  # TODO: exithook
        cnn, addr = plainsocket.accept()
        eventlet.spawn_n(_tlsstartup, cnn)


def _tlsstartup(cnn):
    authname = None
    cnn = ssl.wrap_socket(cnn, keyfile="/etc/confluent/privkey.pem",
                          certfile="/etc/confluent/srvcert.pem",
                          ssl_version=ssl.PROTOCOL_TLSv1,
                          server_side=True)
    sessionhdl(cnn, authname)

def removesocket():
    try:
        os.remove("/var/run/confluent/api.sock")
    except OSError:
        pass

def _unixdomainhandler():
    unixsocket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        os.remove("/var/run/confluent/api.sock")
    except OSError:  # if file does not exist, no big deal
        pass
    if not os.path.isdir("/var/run/confluent"):
        os.makedirs('/var/run/confluent', 0755)
    unixsocket.bind("/var/run/confluent/api.sock")
    os.chmod("/var/run/confluent/api.sock",
             stat.S_IWOTH | stat.S_IROTH | stat.S_IWGRP |
             stat.S_IRGRP | stat.S_IWUSR | stat.S_IRUSR)
    atexit.register(removesocket)
    unixsocket.listen(5)
    while True:
        cnn, addr = unixsocket.accept()
        creds = cnn.getsockopt(socket.SOL_SOCKET, SO_PEERCRED,
                               struct.calcsize('iII'))
        pid, uid, gid = struct.unpack('iII', creds)
        skipauth = False
        if uid in (os.getuid(), 0):
            #this is where we happily accept the person
            #to do whatever.  This allows the server to
            #start with no configuration whatsoever
            #and yet still be configurable by some means
            skipauth = True
            try:
                authname = pwd.getpwuid(uid).pw_name
            except:
                authname = "UNKNOWN SUPERUSER"
        else:
            try:
                authname = pwd.getpwuid(uid).pw_name
            except KeyError:
                cnn.close()
                return
        eventlet.spawn_n(sessionhdl, cnn, authname, skipauth)


class SockApi(object):
    def __init__(self, bindhost=None, bindport=None):
        self.tlsserver = None
        self.unixdomainserver = None
        self.bind_host = bindhost or '::'
        self.bind_port = bindport or 13001

    def start(self):
        global auditlog
        global tracelog
        tracelog = log.Logger('trace')
        auditlog = log.Logger('audit')
        self.tlsserver = eventlet.spawn(
            _tlshandler, self.bind_host, self.bind_port)
        self.unixdomainserver = eventlet.spawn(_unixdomainhandler)
