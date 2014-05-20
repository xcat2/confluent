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
# ALl rights reserved

# This is the socket api layer.
# It implement unix and tls sockets
# 

import os
import pwd
import stat
import struct
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


tracelog = None
auditlog = None
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
        tlvdata.send(self.client, data)

    def startsending(self):
        self.xmit = True
        for datum in self.pendingdata:
            tlvdata.send(self.client, datum)
        self.pendingdata = None


def sessionhdl(connection, authname, skipauth=False):
    # For now, trying to test the console stuff, so let's just do n4.
    authenticated = False
    authdata = None
    cfm = None
    if skipauth:
        authenticated = True
        cfm = configmanager.ConfigManager(tenant=None)
    elif authname:
        authdata = auth.authorize(authname, element=None)
        if authdata is not None:
            cfm = authdata[1]
            authenticated = True
    tlvdata.send(connection, "Confluent -- v0 --")
    while not authenticated:  # prompt for name and passphrase
        tlvdata.send(connection, {'authpassed': 0})
        response = tlvdata.recv(connection)
        authname = response['username']
        passphrase = response['passphrase']
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
    tlvdata.send(connection, {'authpassed': 1})
    request = tlvdata.recv(connection)
    while request is not None:
        try:
            process_request(
                connection, request, cfm, authdata, authname, skipauth)
        except exc.ForbiddenRequest:
            tlvdata.send(connection, {'errorcode': 403,
                                      'error': 'Forbidden'})
            tlvdata.send(connection, {'_requestdone': 1})
        except exc.TargetEndpointBadCredentials:
            tlvdata.send(connection, {'errorcode': 502,
                                      'error': 'Bad Credentials'})
            tlvdata.send(connection, {'_requestdone': 1})
        except exc.TargetEndpointUnreachable:
            tlvdata.send(connection, {'errorcode': 504,
                                      'error': 'Unreachable Target'})
            tlvdata.send(connection, {'_requestdone': 1})
        except:
            tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                         event=log.Events.stacktrace)
            tlvdata.send(connection, {'errorcode': 500,
                                      'error': 'Unexpected error'})
            tlvdata.send(connection, {'_requestdone': 1})
        request = tlvdata.recv(connection)


def send_response(responses, connection):
    if responses is None:
        return
    for rsp in responses:
        tlvdata.send(connection, rsp.raw())
    tlvdata.send(connection, {'_requestdone': 1})


def process_request(connection, request, cfm, authdata, authname, skipauth):
    #TODO(jbjohnso): authorize each request
    if not isinstance(request, dict):
        raise ValueError
    operation = request['operation']
    path = request['path']
    params = request.get('parameters', None)
    hdlr = None
    if not skipauth:
        authdata = auth.authorize(authdata[2], path, authdata[3], operation)
        auditmsg = {
            'operation': operation,
            'user': authdata[2],
            'target': path,
        }
        if authdata[3] is not None:
            auditmsg['tenant'] = authdata[3]
        if authdata is None:
            auditmsg['allowed'] = False
            auditlog.log(auditmsg)
            raise exc.ForbiddenRequest()
        auditmsg['allowed'] = True
        auditlog.log(auditmsg)
    try:
        if operation == 'start':
            elems = path.split('/')
            if elems[3] != "console":
                raise exc.InvalidArgumentException()
            node = elems[2]
            ccons = ClientConsole(connection)
            consession = consoleserver.ConsoleSession(
                node=node, configmanager=cfm, username=authname,
                datacallback=ccons.sendall)
            if consession is None:
                raise Exception("TODO")
            tlvdata.send(connection, {'started': 1})
            ccons.startsending()
            while consession is not None:
                data = tlvdata.recv(connection)
                if type(data) == dict:
                    if data['operation'] == 'stop':
                        consession.destroy()
                        return
                    elif data['operation'] == 'break':
                        consession.send_break()
                        continue
                    else:
                        raise Exception("TODO")
                if not data:
                    consession.destroy()
                    return
                consession.write(data)
        else:
            hdlr = pluginapi.handle_path(path, operation, cfm, params)
    except exc.NotFoundException:
        tlvdata.send(connection, {"errorcode": 404,
                                  "error": "Target not found"})
        tlvdata.send(connection, {"_requestdone": 1})
    except exc.InvalidArgumentException as e:
        tlvdata.send(connection, {"errorcode": 400,
                                  "error": "Bad Request - " + str(e)})
        tlvdata.send(connection, {"_requestdone": 1})
    send_response(hdlr, connection)
    return


def _tlshandler():
    plainsocket = socket.socket(socket.AF_INET6)
    plainsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    plainsocket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    plainsocket.bind(('::', 13001, 0, 0))
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


def _unixdomainhandler():
    unixsocket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        os.remove("/var/run/confluent/api.sock")
    except OSError:  # if file does not exist, no big deal
        pass
    unixsocket.bind("/var/run/confluent/api.sock")
    os.chmod("/var/run/confluent/api.sock",
             stat.S_IWOTH | stat.S_IROTH | stat.S_IWGRP |
             stat.S_IRGRP | stat.S_IWUSR | stat.S_IRUSR)
    unixsocket.listen(5)
    while True:
        cnn, addr = unixsocket.accept()
        creds = cnn.getsockopt(socket.SOL_SOCKET, SO_PEERCRED,
                               struct.calcsize('3i'))
        pid, uid, gid = struct.unpack('3i', creds)
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
    def __init__(self):
        self.tlsserver = None
        self.unixdomainserver = None

    def start(self):
        global auditlog
        global tracelog
        tracelog = log.Logger('trace')
        auditlog = log.Logger('audit')
        self.tlsserver = eventlet.spawn(_tlshandler)
        self.unixdomainserver = eventlet.spawn(_unixdomainhandler)
