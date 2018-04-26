# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2018 Lenovo
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

import base64
import confluent.collective.invites as invites
import confluent.config.configmanager as cfm
import confluent.tlvdata as tlvdata
import confluent.util as util
import eventlet.green.socket as socket
import eventlet.green.ssl as ssl
try:
    import OpenSSL.crypto as crypto
except ImportError:
    # while not always required, we use pyopenssl required for at least
    # collective
    crypto = None

currentleader = None


def handle_connection(connection, cert, request, local=False):
    global currentleader
    operation = request['operation']
    if cert:
        cert = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
    else:
        if not local:
            return
        if 'invite' == operation:
            name = request['name']
            invitation = invites.create_server_invitation(name)
            tlvdata.send(connection,
                         {'collective': {'invitation': invitation}})
        if 'join' == operation:
            invitation = request['invitation']
            invitation = base64.b64decode(invitation)
            name, invitation = invitation.split('@', 1)
            host = request['server']
            remote = socket.create_connection((host, 13001))
            # This isn't what it looks like.  We do CERT_NONE to disable
            # openssl verification, but then use the invitation as a
            # shared secret to validate the certs as part of the join
            # operation
            remote = ssl.wrap_socket(remote,  cert_reqs=ssl.CERT_NONE,
                                     keyfile='/etc/confluent/privkey.pem',
                                     certfile='/etc/confluent/srvcert.pem')
            mycert = util.get_certificate_from_file(
                '/etc/confluent/srvcert.pem')
            cert = remote.getpeercert(binary_form=True)
            proof = base64.b64encode(invites.create_client_proof(
                invitation, mycert, cert))
            tlvdata.recv(remote)  # ignore banner
            tlvdata.recv(remote)  # ignore authpassed: 0
            tlvdata.send(remote, {'collective': {'operation': 'joinchallenge',
                                                 'name': name, 'hmac': proof}})
            rsp = tlvdata.recv(remote)
            proof = rsp['collective']['approval']
            proof = base64.b64decode(proof)
            j = invites.check_server_proof(invitation, mycert, cert, proof)
            if not j:
                return
            tlvdata.send(connection, {'collective': {'status': 'Success'}})
            currentleader = rsp['collective']['leader']
    if 'joinchallenge' == operation:
        mycert = util.get_certificate_from_file('/etc/confluent/srvcert.pem')
        proof = base64.b64decode(request['hmac'])
        myrsp = invites.check_client_proof(request['name'], mycert,
                                           cert, proof)
        if not myrsp:
            tlvdata.send(connection, {'error': 'Invalid token'})
            connection.close()
            return
        myrsp = base64.b64encode(myrsp)
        fprint = util.get_fingerprint(cert)
        cfm.add_collective_member(request['name'],
                                  connection.getpeername()[0], fprint)
        tlvdata.send(connection,
                     {'collective': {'approval': myrsp,
                                     'leader': get_leader(connection)}})
    if 'connect' == operation:
        myself = connection.getsockname()[0]
        if myself != get_leader(connection):
            tlvdata.send(
                connection,
                {'error': 'Cannot assimilate, our leader is '
                          'in another castle', 'leader': currentleader})
            return
        drone = request['name']
        droneinfo = cfm.get_collective_member(drone)
        if not util.cert_matches(droneinfo['fingerprint'], cert):
            tlvdata.send(connection,
                         {'error': 'Invalid certificate,'
                                   'redo invitation process'})
            return
        # ok, we have a connecting member whose certificate checks out
        # He needs to bootstrap his configuration and subscribe it to updates

def get_leader(connection):
    global currentleader
    if currentleader is None:
        currentleader = connection.getsockname()[0]
    return currentleader
