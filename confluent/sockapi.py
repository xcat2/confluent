# Copyright 2013 IBM Corporation
# ALl rights reserved

# This is the socket api layer.
# It implement unix and tls sockets
# 
# TODO: SO_PEERCRED for unix socket
import confluent.auth as auth
import confluent.common.tlvdata as tlvdata
import confluent.consoleserver as consoleserver
import confluent.config.configmanager as configmanager
import eventlet.green.socket as socket
import eventlet.green.ssl as ssl
import eventlet
import os
import struct

SO_PEERCRED = 17

class ClientConsole(object):
    def __init__(self, client):
        self.client = client

    def sendall(self, data):
        tlvdata.send_tlvdata(self.client, data)

def sessionhdl(connection, authname):
    # For now, trying to test the console stuff, so let's just do n4.
    authenticated = False
    if authname and isinstance(authname, bool):
        authenticated = True
        cfm = configmanager.ConfigManager(tenant=None)
    elif authname:
        authenticated = True
        authdata = auth.authorize(authname, element=None)
        cfm = authdata[1]
        authenticated = True
    tlvdata.send_tlvdata(connection,"Confluent -- v0 --")
    while not authenticated:  # prompt for name and passphrase
        tlvdata.send_tlvdata(connection, {'authpassed': 0})
        response = tlvdata.recv_tlvdata(connection)
        username = response['username']
        passphrase = response['passphrase']
        # NOTE(jbjohnso): Here, we need to authenticate, but not
        # authorize a user.  When authorization starts understanding
        # element path, that authorization will need to be called
        # per request the user makes
        authdata = auth.check_user_passphrase(username, passphrase)
        if authdata is None:
            tlvdata.send_tlvdata(connection, {'authpassed': 0})
        else:
            authenticated = True
            cfm = authdata[1]
    tlvdata.send_tlvdata(connection, {'authpassed': 1})
    ccons = ClientConsole(connection)
    consession = consoleserver.ConsoleSession(node='n4', configmanager=cfm,
                                        datacallback=ccons.sendall)
    while (1):
        data = tlvdata.recv_tlvdata(connection)
        if not data:
            consession.destroy()
            return
        consession.write(data)


def _tlshandler():
    plainsocket = socket.socket()
    plainsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv = ssl.wrap_socket(plainsocket, keyfile="/etc/confluent/privkey.pem",
                    certfile="/etc/confluent/srvcert.pem",
                    ssl_version=ssl.PROTOCOL_TLSv1,
                    server_side=True)
    srv.bind(('0.0.0.0', 4001))
    srv.listen(5)
    authname = None
    while (1):  # TODO: exithook
        cnn, addr = srv.accept()
        eventlet.spawn_n(sessionhdl, cnn, authname)


def _unixdomainhandler():
    unixsocket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        os.remove("/var/run/confluent/api.sock")
    except OSError:  # if file does not exist, no big deal
        pass
    unixsocket.bind("/var/run/confluent/api.sock")
    unixsocket.listen(5)
    while (1):
        cnn, addr = unixsocket.accept()
        creds = cnn.getsockopt(socket.SOL_SOCKET, SO_PEERCRED,
                                struct.calcsize('3i'))
        pid, uid, gid = struct.unpack('3i',creds)
        if uid in (os.getuid(), 0):
            #this is where we happily accept the person
            #to do whatever.  This allows the server to
            #start with no configuration whatsoever
            #and yet still be configurable by some means
            authname = True
        else:
            try:
                authname = pwd.getpwuid(uid).pw_name
            except KeyError:
                cnn.close()
                return
        eventlet.spawn_n(sessionhdl, cnn, authname)



class SockApi(object):
    def start(self):
        self.tlsserver = eventlet.spawn(_tlshandler)
        self.unixdomainserver = eventlet.spawn(_unixdomainhandler)
