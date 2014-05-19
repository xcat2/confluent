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

import anydbm as dbm
import errno
import hashlib
import os
import socket
import ssl
import confluent.tlvdata as tlvdata

SO_PASSCRED = 16


def _parseserver(string):
    if ']:' in string:
        server, port = string[1:].split(']:')
    elif string[0] == '[':
        server = string[1:-1]
        port = '13001'
    elif ':' in string:
        server, port = string.split(':')
    else:
        server = string
        port = '13001'
    return server, port


class Command(object):

    def __init__(self, server="/var/run/confluent/api.sock"):
        self.connection = None
        self.serverloc = server
        if os.path.isabs(server) and os.path.exists(server):
            self._connect_unix()
        else:
            self._connect_tls()
        tlvdata.recv(self.connection)
        authdata = tlvdata.recv(self.connection)
        if authdata['authpassed'] == 1:
            self.authenticated = True
        else:
            self.authenticated = False

    def authenticate(self, username, passphrase):
        tlvdata.send(self.connection,
                     {'username': username, 'passphrase': passphrase})
        authdata = tlvdata.recv(self.connection)
        if authdata['authpassed'] == 1:
            self.authenticated = True

    def read(self, path, parameters=None):
        return send_request('retrieve', path, self.connection, parameters)

    def update(self, path, parameters=None):
        return send_request('update', path, self.connection, parameters)

    def create(self, path, parameters=None):
        return send_request('create', path, self.connection, parameters)

    def delete(self, path, parameters=None):
        return send_request('delete', path, self.connection, parameters)

    def _connect_unix(self):
        self.connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.connection.setsockopt(socket.SOL_SOCKET, SO_PASSCRED, 1)
        self.connection.connect(self.serverloc)

    def _connect_tls(self):
        server, port = _parseserver(self.serverloc)
        for res in socket.getaddrinfo(server, port, socket.AF_UNSPEC,
                                      socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res
            try:
                self.connection = socket.socket(af, socktype, proto)
                self.connection.setsockopt(
                    socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except:
                self.connection = None
                continue
            try:
                self.connection.settimeout(5)
                self.connection.connect(sa)
            except:
                raise
                self.connection.close()
                self.connection = None
                continue
            break
        if self.connection is None:
            raise Exception("Failed to connect to %s" % self.serverloc)
        #TODO(jbjohnso): server certificate validation
        clientcfgdir = os.path.join(os.path.expanduser("~"), ".confluent")
        try:
            os.makedirs(clientcfgdir)
        except OSError as exc:
            if not (exc.errno == errno.EEXIST and os.path.isdir(clientcfgdir)):
                raise
        cacert = os.path.join(clientcfgdir, "ca.pem")
        certreqs = ssl.CERT_REQUIRED
        knownhosts = False
        if not os.path.exists(cacert):
            cacert = None
            certreqs = ssl.CERT_NONE
            knownhosts = True
        self.connection = ssl.wrap_socket(self.connection, ca_certs=cacert,
                                          cert_reqs=certreqs,
                                          ssl_version=ssl.PROTOCOL_TLSv1)
        if knownhosts:
            certdata = self.connection.getpeercert(binary_form=True)
            hostid = '@'.join((port,server))
            khf = dbm.open(os.path.join(clientcfgdir, "knownhosts"), 'c', 384)
            if hostid in khf:
                fingerprint = 'sha512$' + hashlib.sha512(certdata).hexdigest()
                if fingerprint == khf[hostid]:
                    return
                else:
                    replace = raw_input(
                        "MISMATCHED CERTIFICATE DATA, ACCEPT NEW? (y/n):")
                    if replace not in ('y', 'Y'):
                        raise Exception("BAD CERTIFICATE")
            print 'Adding new key for %s:%s' % (server, port)
            khf[hostid] = fingerprint



def send_request(operation, path, server, parameters=None):
    """This function iterates over all the responses
    received from the server.

    :param operation:  The operation to request, retrieve, update, delete,
                       create, start, stop
    :param path: The URI path to the resource to operate on
    :param server: The socket to send data over
    :param parameters:  Parameters if any to send along with the request
    """
    payload = {'operation': operation, 'path': path}
    if parameters is not None:
        payload['parameters'] = parameters
    tlvdata.send(server, payload)
    result = tlvdata.recv(server)
    while '_requestdone' not in result:
        yield result
        result = tlvdata.recv(server)
