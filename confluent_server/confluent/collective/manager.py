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
import eventlet
import eventlet.green.socket as socket
import eventlet.green.ssl as ssl
try:
    import OpenSSL.crypto as crypto
except ImportError:
    # while not always required, we use pyopenssl required for at least
    # collective
    crypto = None

currentleader = None


def connect_to_leader(cert=None, name=None, leader=None):
    global currentleader
    if leader is None:
        leader = currentleader
    try:
        remote = socket.create_connection((leader, 13001))
    except socket.error:
        return
    # TLS cert validation is custom and will not pass normal CA vetting
    # to override completely in the right place requires enormous effort, so just defer until after connect
    remote = ssl.wrap_socket(remote, cert_reqs=ssl.CERT_NONE, keyfile='/etc/confluent/privkey.pem',
                             certfile='/etc/confluent/srvcert.pem')
    if cert:
        fprint = util.get_fingerprint(cert)
    else:
        collent = cfm.get_collective_member_by_address(leader)
        fprint = collent['fingerprint']
    if not util.cert_matches(fprint, remote.getpeercert(binary_form=True)):
        # probably Janeway up to something
        raise Exception("Certificate mismatch in the collective")
    tlvdata.recv(remote)  # the banner
    tlvdata.recv(remote)  # authpassed... 0..
    if name is None:
        name = get_myname()
    tlvdata.send(remote, {'collective': {'operation': 'connect',
                                         'name': name,
                                         'txcount': cfm._txcount}})
    keydata = tlvdata.recv(remote)
    if 'error' in keydata:
        if 'leader' in keydata:
            ldrc = cfm.get_collective_member_by_address(keydata['leader'])
            if ldrc and ldrc['name'] == name:
                raise Exception("Redirected to self")
            return connect_to_leader(name=name, leader=keydata['leader'])
        raise Exception(keydata['error'])
    colldata = tlvdata.recv(remote)
    globaldata = tlvdata.recv(remote)
    dbsize = tlvdata.recv(remote)['dbsize']
    dbjson = ''
    while (len(dbjson) < dbsize):
        ndata = remote.recv(dbsize - len(dbjson))
        if not ndata:
            raise Exception("Error doing initial DB transfer")
        dbjson += ndata
    cfm.cfgleader = None
    cfm.clear_configuration()
    cfm._restore_keys(keydata, None)
    for c in colldata:
        cfm.add_collective_member(c, colldata[c]['address'],
                                  colldata[c]['fingerprint'])
    cfm._cfgstore['collective'] = colldata
    for globvar in globaldata:
        cfm.set_global(globvar, globaldata[globvar])
    cfm.ConfigManager(tenant=None)._load_from_json(dbjson)
    cfm.ConfigManager._bg_sync_to_file()
    currentleader = leader
    cfm.follow_channel(remote)
    # The leader has folded, time to startup again...
    eventlet.spawn_n(start_collective)

def get_myname():
    try:
        with open('/etc/confluent/cfg/myname', 'r') as f:
            return f.read()
    except IOError:
        myname = socket.gethostname()
        with open('/etc/confluent/cfg/myname', 'w') as f:
            f.write(myname)
        return myname

def handle_connection(connection, cert, request, local=False):
    global currentleader
    operation = request['operation']
    if cert:
        cert = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
    else:
        if not local:
            return
        if 'invite' == operation:
            #TODO(jjohnson2): Cannot do the invitation if not the head node, the certificate hand-carrying
            #can't work in such a case.
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
            tlvdata.send(remote, {'collective': {'operation': 'enroll',
                                                 'name': name, 'hmac': proof}})
            rsp = tlvdata.recv(remote)
            proof = rsp['collective']['approval']
            proof = base64.b64decode(proof)
            j = invites.check_server_proof(invitation, mycert, cert, proof)
            if not j:
                return
            tlvdata.send(connection, {'collective': {'status': 'Success'}})
            currentleader = rsp['collective']['leader']
            f = open('/etc/confluent/cfg/myname', 'w')
            f.write(name)
            f.close()
            eventlet.spawn_n(connect_to_leader, cert, name)
    if 'enroll' == operation:
        #TODO(jjohnson2): error appropriately when asked to enroll, but the master is elsewhere
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
        myfprint = util.get_fingerprint(mycert)
        cfm.add_collective_member(get_myname(),
                                  connection.getsockname()[0], myfprint)
        cfm.add_collective_member(request['name'],
                                  connection.getpeername()[0], fprint)
        tlvdata.send(connection,
                     {'collective': {'approval': myrsp,
                                     'leader': get_leader(connection)}})
    if 'assimilate' == operation:
        drone = request['name']
        droneinfo = cfm.get_collective_member(drone)
        if not util.cert_matches(droneinfo['fingerprint'], cert):
            tlvdata.send(connection,
                         {'error': 'Invalid certificate, '
                                   'redo invitation process'})
            return
        if request['txcount'] < cfm._txcount:
            tlvdata.send(connection,
                         {'error': 'Refusing to be assimilated by inferior'
                                   'transaction count',
                          'txcount': cfm._txcount})
            return
        eventlet.spawn_n(connect_to_leader, None, None,
                         leader=connection.getpeername()[0])
        tlvdata.send(connection, {'status': 0})
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
                         {'error': 'Invalid certificate, '
                                   'redo invitation process'})
            return
        if request['txcount'] > cfm._txcount:
            retire_as_leader()
            tlvdata.send(connection,
                         {'error': 'Client has higher tranasaction count, '
                                   'should assimilate me, connecting..',
                          'txcount': cfm._txcount})
            eventlet.spawn_n(connect_to_leader, None, None,
                             connection.getpeername()[0])
            return
        tlvdata.send(connection, cfm._dump_keys(None, False))
        tlvdata.send(connection, cfm._cfgstore['collective'])
        tlvdata.send(connection, cfm.get_globals())
        cfgdata = cfm.ConfigManager(None)._dump_to_json()
        tlvdata.send(connection, {'dbsize': len(cfgdata)})
        connection.sendall(cfgdata)
        #tlvdata.send(connection, {'tenants': 0}) # skip the tenants for now,
        # so far unused anyway
        cfm.cfgleader = None
        cfm.relay_slaved_requests(drone, connection)
        # ok, we have a connecting member whose certificate checks out
        # He needs to bootstrap his configuration and subscribe it to updates

def try_assimilate(drone):
    pass

def get_leader(connection):
    if currentleader is None or connection.getpeername()[0] == currentleader:
        become_leader(connection)
    return currentleader

def retire_as_leader():
    global currentleader
    cfm.stop_leading()
    currentleader = None

def become_leader(connection):
    global currentleader
    currentleader = connection.getsockname()[0]
    skipaddr = connection.getpeername()[0]
    for member in cfm.list_collective():
        dronecandidate = cfm.get_collective_member(member)['address']
        if dronecandidate in (currentleader, skipaddr):
            continue
        eventlet.spawn_n(try_assimilate, dronecandidate)


def startup():
    members = list(cfm.list_collective())
    if len(members) < 2:
        # Not in collective mode, return
        return
    eventlet.spawn_n(start_collective)

def start_collective():
    myname = get_myname()
    for member in cfm.list_collective():
        if member == myname:
            continue
        if cfm.cfgleader is None:
            cfm.cfgleader = True
        ldrcandidate = cfm.get_collective_member(member)['address']
        connect_to_leader(name=myname, leader=ldrcandidate)

