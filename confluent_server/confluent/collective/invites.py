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

# This handles the process of generating and tracking/validating invites

import base64
import hashlib
import hmac
import os
pending_invites = {}

def create_server_invitation(servername, role):
    servername = servername.encode('utf-8')
    randbytes = (3 - ((len(servername) + 2) % 3)) % 3 + 64
    invitation = os.urandom(randbytes)
    pending_invites[servername] = {'invitation': invitation, 'role': role}
    invite = servername + b'@' + invitation
    return base64.b64encode(invite)

def create_client_proof(invitation, mycert, peercert):
    return hmac.new(invitation, peercert + mycert, hashlib.sha256).digest()

def check_server_proof(invitation, mycert, peercert, proof):
    validproof = hmac.new(invitation, mycert + peercert, hashlib.sha256
                          ).digest()
    return proof == validproof

def check_client_proof(servername, mycert, peercert, proof):
    servername = servername.encode('utf-8')
    if servername not in pending_invites:
        return False, None
    invitation = pending_invites[servername]
    role = invitation['role']
    invitation = invitation['invitation']
    validproof = hmac.new(invitation, mycert + peercert, hashlib.sha256
                          ).digest()
    if proof == validproof:
        # We know that the client knew the secret, and that it measured our
        # certificate, and thus calling code can bless the certificate, and
        # we can forget the invitation
        del pending_invites[servername]
        # We now want to prove to the client that we also know the secret,
        # and that we measured their certificate well
        # Now to generate an answer...., reverse the cert order so our answer
        # is different, but still proving things
        return hmac.new(invitation, peercert + mycert, hashlib.sha256
                          ).digest(), role
    # The given proof did not verify the invitation
    return False, None

