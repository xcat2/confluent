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
import confluent.swarm.invites as invites
import confluent.tlvdata as tlvdata
import confluent.util as util
import eventlet.green.socket as socket
import eventlet.green.ssl as ssl
try:
    import OpenSSL.crypto as crypto
except ImportError:
    # while not always required, we use pyopenssl required for at least swarm
    crypto = None

swarmcerts = {}


def handle_connection(connection, cert, swarmrequest, local=False):
    operation = swarmrequest['operation']
    if cert:
        cert = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
    else:
        if not local:
            return
        if 'invite' == operation:
            name = swarmrequest['invite']['name']
            invitation = invites.create_server_invitation(name)
            tlvdata.send(connection, {'swarm': {'invitation': invitation}})
        if 'join' == operation:
            invitation = swarmrequest['invitation']
            invitation = base64.b64decode(invitation)
            name, invitation = invitation.split('@')
            host = swarmrequest['server']
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
            tlvdata.send(remote, {'swarm': {'operation': 'joinchallenge',
                                            'name': name, 'hmac': proof}})
            rsp = tlvdata.recv(remote)
            proof = rsp['swarm']['approval']
            j = invites.check_server_proof(invitation, mycert, cert, proof)
            if not j:
                return
    if 'joinchallenge' == operation:
        mycert = util.get_certificate_from_file('/etc/confluent/srvcert.pem')
        proof = base64.b64decode(swarmrequest['hmac'])
        myrsp = invites.check_client_proof(swarmrequest['name'], mycert,
                                           cert, proof)
        if not myrsp:
            connection.close()
            return
        myrsp = base64.b64encode(myrsp)
        swarmcerts[swarmrequest['name']] = cert
        tlvdata.send(connection, {'swarm': {'approval': myrsp}})
        clientready = tlvdata.recv(connection)
        print(repr(clientready))
