# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
# Copyright 2015-2019 Lenovo
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
import asyncio
import ctypes
import ctypes.util
import errno
import os
import pwd
import stat
import struct
import sys
import traceback

import socket
import ssl

import confluent.auth as auth
import confluent.credserver as credserver
import confluent.config.conf as conf
import confluent.asynctlvdata as tlvdata
import confluent.consoleserver as consoleserver
import confluent.config.configmanager as configmanager
import confluent.exceptions as exc
import confluent.log as log
import confluent.core as pluginapi
import confluent.shellserver as shellserver
import confluent.collective.manager as collective
import confluent.util as util

tracelog = None
auditlog = None


plainsocket = None

libc = ctypes.CDLL(ctypes.util.find_library('c'))
libssl = ctypes.CDLL(ctypes.util.find_library('ssl'))
libssl.SSL_CTX_set_cert_verify_callback.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]


def _should_authlog(path, operation):
    if (operation == 'retrieve' and
            ('/sensors/' in path or '/health/' in path or
             '/power/state' in path or '/nodes/' == path or
             (path.startswith('/noderange/') and path.endswith('/nodes/')))):
        return False
    return True


class ClientConsole(object):
    def __init__(self, client):
        self.client = client
        self.xmit = False
        self.pendingdata = []

    async def sendall(self, data):
        if not self.xmit:
            self.pendingdata.append(data)
            return
        await send_data(self.client, data)

    async def startsending(self):
        self.xmit = True
        for datum in self.pendingdata:
            await send_data(self.client, datum)
        self.pendingdata = []


async def send_data(connection, data):
    try:
        await tlvdata.send(connection, data)
    except IOError as ie:
        if ie.errno != errno.EPIPE:
            raise


async def sessionhdl(connection, authname, skipauth=False, cert=None):
    try:
        # For now, trying to test the console stuff, so let's just do n4.
        authenticated = False
        authdata = None
        cfm = None
        if skipauth:
            authenticated = True
            cfm = configmanager.ConfigManager(tenant=None, username=authname)
        elif authname:
            authdata = auth.authorize(authname, element=None)
            if authdata:
                cfm = authdata[1]
                authenticated = True
        # version 0 == original, version 1 == pickle3 allowed,
        # v2 = pickle forbidden, msgpack allowed
        # v3 - filehandle allowed
        # v4 - schema change and keepalive changes

        await send_data(connection, "Confluent -- v4 --")
        while not authenticated:  # prompt for name and passphrase
            await send_data(connection, {'authpassed': 0})
            response = await tlvdata.recv(connection)
            if not response:
                return
            if 'collective' in response:
                return await collective.handle_connection(connection, cert,
                                                    response['collective'])
            while not configmanager.config_is_ready():
                await asyncio.sleep(1)
            if 'dispatch' in response:
                dreq = await tlvdata.recvall(
                    connection, response['dispatch']['length'])
                return await pluginapi.handle_dispatch(connection, cert, dreq,
                                                 response['dispatch']['name'])
            if 'proxyconsole' in response:
                return await start_proxy_term(connection, cert,
                                        response['proxyconsole'])
            authname = response['username']
            passphrase = response['password']
            # note(jbjohnso): here, we need to authenticate, but not
            # authorize a user.  When authorization starts understanding
            # element path, that authorization will need to be called
            # per request the user makes
            authdata = await auth.check_user_passphrase(authname, passphrase)
            if not authdata:
                auditlog.log(
                    {'operation': 'connect',
                     'user': authname, 'allowed': False})
            else:
                authenticated = True
                cfm = authdata[1]
        await send_data(connection, {'authpassed': 1})
        request = await tlvdata.recv(connection)
        if request and isinstance(request, dict) and 'collective' in request:
            if skipauth:
                return await collective.handle_connection(
                    connection, None, request['collective'], local=True)
            else:
                tlvdata.send(
                    connection,
                    {'collective': {
                        'error': 'collective management commands '
                                 'may only be used by root'}})
        while request is not None:
            try:
                await process_request(
                    connection, request, cfm, authdata, authname, skipauth)
            except exc.ConfluentException as e:
                if ((not isinstance(e, exc.LockedCredentials)) and
                        e.apierrorcode == 500):
                    tracelog.log(
                        traceback.format_exc(), ltype=log.DataTypes.event,
                        event=log.Events.stacktrace)
                await send_data(connection, {'errorcode': e.apierrorcode,
                                             'error': e.apierrorstr,
                                             'detail': e.get_error_body()})
                await send_data(connection, {'_requestdone': 1})
            except SystemExit:
                sys.exit(0)
            except Exception as e:
                tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                             event=log.Events.stacktrace)
                await send_data(
                    connection,
                    {'errorcode': 500,
                     'error': 'Unexpected error - ' + str(e)})
                await send_data(connection, {'_requestdone': 1})
            try:
                request = await tlvdata.recv(connection)
            except Exception:
                request = None
    finally:
        if cfm:
            cfm.close_client_files()
        try:
            if isinstance(connection, tuple):
                connection[1].close()
                await connection[1].wait_closed()
                connection = connection[1].get_extra_info('socket')
            else:
                connection.close()
        except Exception as e:
            print(repr(e))
            pass


async def send_response(responses, connection):
    if responses is None:
        return
    responses = await responses
    if responses is None:
        return
    async for rsp in pluginapi.iterate_responses(responses):
        await send_data(connection, rsp.raw())
    await send_data(connection, {'_requestdone': 1})


async def process_request(
        connection, request, cfm, authdata, authname, skipauth):
    if isinstance(request, tlvdata.ClientFile):
        cfm.add_client_file(request)
        return
    if not isinstance(request, dict):
        raise exc.InvalidArgumentException
    operation = request['operation']
    path = request['path']
    params = request.get('parameters', {})
    hdlr = None
    auditmsg = {
        'operation': operation,
        'target': path,
    }
    if not skipauth:
        authdata = auth.authorize(authdata[2], path, authdata[3], operation)
        if not authdata:
            auditmsg['allowed'] = False
            auditlog.log(auditmsg)
            raise exc.ForbiddenRequest()
        auditmsg['user'] = authdata[2]
        if authdata[3] is not None:
            auditmsg['tenant'] = authdata[3]
    auditmsg['allowed'] = True
    if _should_authlog(path, operation):
        tlvdata.unicode_dictvalues(auditmsg)
        auditlog.log(auditmsg)
    try:
        if operation == 'start':
            return await start_term(authname, cfm, connection, params, path,
                              authdata, skipauth)
        elif operation == 'shutdown' and skipauth:
            configmanager.ConfigManager.shutdown()
        else:
            hdlr = pluginapi.handle_path(path, operation, cfm, params)
    except exc.NotFoundException as e:
        send_data(connection, {"errorcode": 404,
                               "error": "Target not found - " + str(e)})
        send_data(connection, {"_requestdone": 1})
    except exc.InvalidArgumentException as e:
        await send_data(connection, {"errorcode": 400,
                               "error": "Bad Request - " + str(e)})
        await send_data(connection, {"_requestdone": 1})
    await send_response(hdlr, connection)
    return


async def start_proxy_term(connection, cert, request):
    droneinfo = configmanager.get_collective_member(request['name'])
    if not util.cert_matches(droneinfo['fingerprint'], cert):
        connection.close()
        return
    cfm = configmanager.ConfigManager(request['tenant'])
    ccons = ClientConsole(connection)
    consession = consoleserver.ConsoleSession(
        node=request['node'], configmanager=cfm, username=request['user'],
        datacallback=ccons.sendall, skipreplay=request['skipreplay'],
        direct=False, width=request.get('width', 80), height=request.get(
            'height', 24))
    await term_interact(None, None, ccons, None, connection, consession, None)


async def start_term(authname, cfm, connection, params, path, authdata, skipauth):
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
            sessionid=sessionid, width=params.get('width', 80),
            height=params.get('height', 24))
    else:
        raise exc.InvalidArgumentException('Invalid path {0}'.format(path))
    if consession is None:
        raise Exception("TODO")
    await term_interact(authdata, authname, ccons, cfm, connection, consession,
                  skipauth)


async def term_interact(authdata, authname, ccons, cfm, connection, consession,
                  skipauth):
    await send_data(connection, {'started': 1})
    await ccons.startsending()
    bufferage = consession.get_buffer_age()
    if bufferage is not False:
        await send_data(connection, {'bufferage': bufferage})
    while consession is not None:
        try:
            data = await tlvdata.recv(connection)
        except Exception:
            data = None
        if type(data) == dict:
            if data['operation'] == 'stop':
                await consession.destroy()
                break
            elif data['operation'] == 'break':
                consession.send_break()
                continue
            elif data['operation'] == 'reopen':
                consession.reopen()
                continue
            elif data['operation'] == 'pause':
                ccons.xmit = False
                continue
            elif data['operation'] == 'resume':
                ccons.xmit = True
                continue
            elif data['operation'] == 'resize':
                consession.resize(width=data['width'], height=data['height'])
                continue
            else:
                try:
                    await process_request(connection, data, cfm, authdata, authname,
                                          skipauth)
                except Exception as e:
                    tracelog.log(traceback.format_exc(),
                                 ltype=log.DataTypes.event,
                                 event=log.Events.stacktrace)
                    await send_data(
                        connection,
                        {'errorcode': 500,
                         'error': 'Unexpected error - ' + str(e)})
                    await send_data(connection, {'_requestdone': 1})
                continue
        if not consession:
            break
        if not data:
            await consession.destroy()
            break
        await consession.write(data)
    await tlvdata.close(connection)


async def _tlshandler(bind_host, bind_port):
    global plainsocket
    plainsocket = socket.socket(socket.AF_INET6)
    plainsocket.settimeout(0)
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
            await asyncio.sleep(1)
    # Enable TCP_FASTOPEN
    plainsocket.setsockopt(socket.SOL_TCP, 23, 5)
    plainsocket.listen(5)
    cs = credserver.CredServer()
    cloop = asyncio.get_event_loop()
    while (1):  # TODO: exithook
        cnn, addr = await cloop.sock_accept(plainsocket)
        if addr[1] < 1000:
            asyncio.create_task(cs.handle_client(cnn, addr))
        else:
            asyncio.create_task(_tlsstartup(cnn))

@ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
def verify_stub(store, misc):
    return 1

class PyObject_HEAD(ctypes.Structure):
    _fields_ = [
        ("ob_refcnt",    ctypes.c_ssize_t),
        ("ob_type",      ctypes.c_void_p),
    ]


# see main/Modules/_ssl.c, only caring about the SSL_CTX pointer
class PySSLContext(ctypes.Structure):
    _fields_ = [
        ("ob_base",      PyObject_HEAD),
        ("ctx",         ctypes.c_void_p),
    ]

@ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
def verify_stub(store, misc):
    return 1


class PyObject_HEAD(ctypes.Structure):
    _fields_ = [
        ("ob_refcnt",    ctypes.c_ssize_t),
        ("ob_type",      ctypes.c_void_p),
    ]


# see main/Modules/_ssl.c, only caring about the SSL_CTX pointer
class PySSLContext(ctypes.Structure):
    _fields_ = [
        ("ob_base",      PyObject_HEAD),
        ("ctx",         ctypes.c_void_p),
    ]


async def _tlsstartup(cnn):
    authname = None
    cloop = asyncio.get_event_loop()
    cert = None
    conf.init_config()
    configfile = conf.get_config()
    if configfile.has_option('security', 'cipher_list'):
        ciphers = configfile.get('security', 'cipher_list')
    else:
        ciphers = 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384'
    try:
        # Try relatively newer python TLS function
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
        ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        ctx.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
        ctx.verify_mode = ssl.CERT_OPTIONAL
        ctx.set_ciphers(ciphers)
        ctx.load_cert_chain('/etc/confluent/srvcert.pem',
                            '/etc/confluent/privkey.pem')
        ssl_ctx = PySSLContext.from_address(id(ctx)).ctx
        libssl.SSL_CTX_set_cert_verify_callback(ssl_ctx, verify_stub, 0)
        sreader = asyncio.StreamReader()
        sreaderprot = asyncio.StreamReaderProtocol(sreader)
        tport, _ = await cloop.connect_accepted_socket(
            lambda: sreaderprot, sock=cnn, ssl=ctx)
        swriter = asyncio.StreamWriter(tport, sreaderprot, sreader, cloop)
        cert = tport.get_extra_info('ssl_object').getpeercert(binary_form=True)
        cnn = (sreader, swriter)
        #cnn = ctx.wrap_socket(cnn, server_side=True)
    except AttributeError:
        raise Exception('Unable to find workable SSL support')
    asyncio.create_task(sessionhdl(cnn, authname, cert=cert))

def removesocket():
    try:
        os.remove("/var/run/confluent/api.sock")
    except OSError:
        pass

async def _unixdomainhandler():
    aloop = asyncio.get_event_loop()
    unixsocket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    unixsocket.settimeout(0)
    try:
        os.remove("/var/run/confluent/api.sock")
    except OSError:  # if file does not exist, no big deal
        pass
    if not os.path.isdir("/var/run/confluent"):
        os.makedirs('/var/run/confluent', 0o755)
    unixsocket.bind("/var/run/confluent/api.sock")
    os.chmod("/var/run/confluent/api.sock",
             stat.S_IWOTH | stat.S_IROTH | stat.S_IWGRP |
             stat.S_IRGRP | stat.S_IWUSR | stat.S_IRUSR)
    atexit.register(removesocket)
    unixsocket.listen(5)
    while True:
        cnn, addr = await aloop.sock_accept(unixsocket)
        creds = cnn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
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
        util.spawn(sessionhdl(cnn, authname, skipauth))
        #asyncio.create_task(sessionhdl(cnn, authname, skipauth))


class SockApi(object):
    def __init__(self, bindhost=None, bindport=None):
        self.tlsserver = None
        self.unixdomainserver = None
        self.bind_host = bindhost or '::'
        self.bind_port = bindport or 13001

    async def start(self):
        global auditlog
        global tracelog
        tracelog = log.Logger('trace')
        auditlog = log.Logger('audit')
        self.tlsserver = None
        if self.should_run_remoteapi():
            self.start_remoteapi()
        else:
            cloop = asyncio.get_event_loop()
            cloop.create_task(self.watch_for_cert())
        self.unixdomainserver = asyncio.create_task(_unixdomainhandler())

    async def watch_for_cert(self):
        watcher = libc.inotify_init1(os.O_NONBLOCK)
        if libc.inotify_add_watch(watcher, b'/etc/confluent/', 0x100) > -1:
            while True:
                currfut = asyncio.Future()
                asyncio.get_event_loop().add_reader(
                    watcher, currfut.set_result, None)
                currfut.add_done_callback(
                    lambda x: asyncio.get_event_loop().remove_reader(watcher))
                done, _ = await asyncio.wait([currfut], return_when=asyncio.FIRST_COMPLETED)
                for currfut in done:
                    await currfut
                try:
                    os.read(watcher, 1024)
                except Exception:
                    pass
                if self.should_run_remoteapi():
                    os.close(watcher)
                    self.start_remoteapi()
                    break

    def should_run_remoteapi(self):
        return os.path.exists("/etc/confluent/srvcert.pem")

    def stop_remoteapi(self):
        if self.tlsserver is None:
            return
        self.tlsserver.cancel()
        plainsocket.close()
        self.tlsserver = None

    def start_remoteapi(self):
        if self.tlsserver is not None:
            return
        self.tlsserver = asyncio.get_event_loop().create_task(
            _tlshandler(self.bind_host, self.bind_port))
