# Copyright 2013 IBM Corporation
# ALl rights reserved

# This is the socket api layer.
# It implement unix and tls sockets
# 
# TODO: SO_PEERCRED for unix socket
import confluent.consoleserver as consoleserver
import confluent.config as config
import eventlet.green.socket as socket
import eventlet.green.ssl as ssl
import eventlet
import os
import struct

SO_PEERCRED = 17

def sessionhdl(connection, authname):
    #TODO: authenticate and authorize peer
    # For now, trying to test the console stuff, so let's just do n1.
    skipauth = False
    if authname and isinstance(authname, bool):
        skipauth = True
    connection.sendall("Confluent -- v0 --\r\n")
    if authname is None:  # prompt for name and passphrase
        connection.sendall("Name: ")
        username = connection.recv(4096)
        connection.sendall(username)
        while "\r" not in username:
            ddata = connection.recv(4096)
            if not ddata:
                return
            connection.sendall(ddata)
            username += ddata
        username, _, passphrase = username.partition("\r")
        connection.sendall("\nPassphrase: ")
        while "\r" not in passphrase:
            pdata = connection.recv(4096)
            if not pdata:
                return
            passphrase += pdata
        connection.sendall("\r\n")
        print username
        print passphrase
    connection.sendall("Confluent -- v0 -- Session Granted\r\n/->")
    cfm = config.ConfigManager(tenant=0)
    consession = consoleserver.ConsoleSession(node='n1', configmanager=cfm,
                                        datacallback=connection.sendall)
    while (1):
        data = connection.recv(4096)
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
