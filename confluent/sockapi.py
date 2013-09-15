# Copyright 2013 IBM Corporation
# ALl rights reserved

# This is the socket api layer.
# It implement unix and tls sockets
# TODO: SO_PEERCRED for unix socket
import confluent.console as console
import confluent.config as config
import eventlet.green.socket as socket
import eventlet.green.ssl as ssl
import eventlet

def sessionhdl(connection):
    #TODO: authenticate and authorize peer
    # For now, trying to test the console stuff, so let's just do n1.
    cfm = config.ConfigManager(tenant=0)
    consession = console.ConsoleSession(node='n1', configmanager=cfm,
                                        datacallback=connection.write)
    while (1):
        data = connection.read()
        consession.write(data)


def _handler():
    plainsocket = socket.socket()
    srv = ssl.wrap_socket(plainsocket, keyfile="/etc/confluent/privkey.pem",
                    certfile="/etc/confluent/srvcert.pem",
                    ssl_version=ssl.PROTOCOL_TLSv1,
                    server_side=True)
    srv.bind(('0.0.0.0', 4001))
    srv.listen(5)
    while (1):  # TODO: exithook
        cnn, addr = srv.accept()
        eventlet.spawn_n(sessionhdl, cnn)

class SockApi(object):
    def start(self):
        self.server = eventlet.spawn(_handler)
