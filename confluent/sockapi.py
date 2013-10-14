# Copyright 2013 IBM Corporation
# ALl rights reserved

# This is the socket api layer.
# It implement unix and tls sockets
# 
# TODO: SO_PEERCRED for unix socket
import confluent.console as console
import confluent.config as config
import eventlet.green.socket as socket
import eventlet.green.ssl as ssl
import eventlet
import os
import struct

SO_PEERCRED = 17

def sessionhdl(connection):
    #TODO: authenticate and authorize peer
    # For now, trying to test the console stuff, so let's just do n1.
    cfm = config.ConfigManager(tenant=0)
    consession = console.ConsoleSession(node='n1', configmanager=cfm,
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
    while (1):  # TODO: exithook
        cnn, addr = srv.accept()
        eventlet.spawn_n(sessionhdl, cnn)


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
        print struct.unpack('3i',creds)
        eventlet.spawn_n(sessionhdl, cnn)



class SockApi(object):
    def start(self):
        self.tlsserver = eventlet.spawn(_tlshandler)
        self.unixdomainserver = eventlet.spawn(_unixdomainhandler)
