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
import confluent.exceptions as exc
import confluent.log as log
import confluent.tlvdata as tlvdata
import confluent.util as util
import eventlet
import eventlet.green.socket as socket
import eventlet.green.ssl as ssl
import eventlet.green.threading as threading
import greenlet
import random
try:
    import OpenSSL.crypto as crypto
except ImportError:
    # while not always required, we use pyopenssl required for at least
    # collective
    crypto = None

currentleader = None
cfginitlock = None
follower = None
retrythread = None

class ContextBool(object):
    def __init__(self):
        self.active = False

    def __enter__(self):
        self.active = True

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.active = False

connecting = ContextBool()
leader_init = ContextBool()

def connect_to_leader(cert=None, name=None, leader=None):
    global currentleader
    global cfginitlock
    global follower
    if cfginitlock is None:
        cfginitlock = threading.RLock()
    if leader is None:
        leader = currentleader
    log.log({'info': 'Attempting connection to leader {0}'.format(leader),
             'subsystem': 'collective'})
    try:
        remote = connect_to_collective(cert, leader)
    except socket.error as e:
        log.log({'error': 'Collective connection attempt to {0} failed: {1}'
                          ''.format(leader, str(e)),
                 'subsystem': 'collective'})
        return False
    with connecting:
        with cfginitlock:
            tlvdata.recv(remote)  # the banner
            tlvdata.recv(remote)  # authpassed... 0..
            if name is None:
                name = get_myname()
            tlvdata.send(remote, {'collective': {'operation': 'connect',
                                                 'name': name,
                                                 'txcount': cfm._txcount}})
            keydata = tlvdata.recv(remote)
            if not keydata:
                return False
            if 'error' in keydata:
                if 'backoff' in keydata:
                    log.log({
                        'info': 'Collective initialization in progress on '
                                '{0}, will retry connection'.format(leader),
                        'subsystem': 'collective'})
                    eventlet.spawn_after(random.random(), connect_to_leader,
                                         cert, name, leader)
                    return True
                if 'leader' in keydata:
                    log.log(
                        {'info': 'Prospective leader {0} has redirected this '
                                 'member to {1}'.format(leader, keydata['leader']),
                         'subsystem': 'collective'})
                    ldrc = cfm.get_collective_member_by_address(
                        keydata['leader'])
                    if ldrc and ldrc['name'] == name:
                        raise Exception("Redirected to self")
                    return connect_to_leader(name=name,
                                             leader=keydata['leader'])
                if 'txcount' in keydata:
                    log.log({'info':
                                 'Prospective leader {0} has inferior '
                                 'transaction count, becoming leader'
                                 ''.format(leader)})
                    return become_leader(remote)
                print(keydata['error'])
                return False
                follower.kill()
                cfm.stop_following()
                follower = None
            log.log({'info': 'Following leader {0}'.format(leader),
                     'subsystem': 'collective'})
            colldata = tlvdata.recv(remote)
            globaldata = tlvdata.recv(remote)
            dbi = tlvdata.recv(remote)
            dbsize = dbi['dbsize']
            dbjson = ''
            while (len(dbjson) < dbsize):
                ndata = remote.recv(dbsize - len(dbjson))
                if not ndata:
                    try:
                        remote.close()
                    except Exception:
                        pass
                    raise Exception("Error doing initial DB transfer")
                dbjson += ndata
            cfm.clear_configuration()
            try:
                cfm._restore_keys(keydata, None, sync=False)
                for c in colldata:
                    cfm._true_add_collective_member(c, colldata[c]['address'],
                                                    colldata[c]['fingerprint'],
                                                    sync=False)
                for globvar in globaldata:
                    cfm.set_global(globvar, globaldata[globvar], False)
                cfm._txcount = dbi.get('txcount', 0)
                cfm.ConfigManager(tenant=None)._load_from_json(dbjson,
                                                               sync=False)
                cfm.commit_clear()
            except Exception:
                cfm.stop_following()
                cfm.rollback_clear()
                raise
            currentleader = leader
        #spawn this as a thread...
        follower = eventlet.spawn(follow_leader, remote)
    return True


def follow_leader(remote):
    global currentleader
    cleanexit = False
    try:
        cfm.follow_channel(remote)
    except greenlet.GreenletExit:
        cleanexit = True
    finally:
        if cleanexit:
            log.log({'info': 'Previous following cleanly closed',
                     'subsystem': 'collective'})
            return
        log.log({'info': 'Current leader has disappeared, restarting '
                         'collective membership', 'subsystem': 'collective'})
        # The leader has folded, time to startup again...
        cfm.stop_following()
        currentleader = None
        eventlet.spawn_n(start_collective)


def connect_to_collective(cert, member):
    remote = socket.create_connection((member, 13001))
    # TLS cert validation is custom and will not pass normal CA vetting
    # to override completely in the right place requires enormous effort, so just defer until after connect
    remote = ssl.wrap_socket(remote, cert_reqs=ssl.CERT_NONE, keyfile='/etc/confluent/privkey.pem',
                             certfile='/etc/confluent/srvcert.pem')
    if cert:
        fprint = cert
    else:
        collent = cfm.get_collective_member_by_address(member)
        fprint = collent['fingerprint']
    if not util.cert_matches(fprint, remote.getpeercert(binary_form=True)):
        # probably Janeway up to something
        raise Exception("Certificate mismatch in the collective")
    return remote


def get_myname():
    try:
        with open('/etc/confluent/cfg/myname', 'r') as f:
            return f.read().strip()
    except IOError:
        myname = socket.gethostname()
        with open('/etc/confluent/cfg/myname', 'w') as f:
            f.write(myname)
        return myname

def handle_connection(connection, cert, request, local=False):
    global currentleader
    global retrythread
    operation = request['operation']
    if cert:
        cert = crypto.dump_certificate(crypto.FILETYPE_ASN1, cert)
    else:
        if not local:
            return

        if 'show' == operation:
            if not list(cfm.list_collective()):
                tlvdata.send(connection,
                             {'collective': {'error': 'Collective mode not '
                                                      'enabled on this '
                                                      'system'}})
                return
            if follower:
                linfo = cfm.get_collective_member_by_address(currentleader)
                remote = socket.create_connection((currentleader, 13001))
                remote = ssl.wrap_socket(remote, cert_reqs=ssl.CERT_NONE,
                                         keyfile='/etc/confluent/privkey.pem',
                                         certfile='/etc/confluent/srvcert.pem')
                cert = remote.getpeercert(binary_form=True)
                if not (linfo and util.cert_matches(
                        linfo['fingerprint'],
                        cert)):
                    remote.close()
                    tlvdata.send(connection,
                                 {'error': 'Invalid certificate, '
                                           'redo invitation process'})
                    connection.close()
                    return
                tlvdata.recv(remote)  # ignore banner
                tlvdata.recv(remote)  # ignore authpassed: 0
                tlvdata.send(remote,
                             {'collective': {'operation': 'getinfo',
                                             'name': get_myname()}})
                collinfo = tlvdata.recv(remote)
            else:
                collinfo = {}
                populate_collinfo(collinfo)
            try:
                cfm.check_quorum()
                collinfo['quorum'] = True
            except exc.DegradedCollective:
                collinfo['quorum'] = False
            tlvdata.send(connection, {'collective':  collinfo})
            return
        if 'invite' == operation:
            try:
                cfm.check_quorum()
            except exc.DegradedCollective:
                tlvdata.send(connection,
                    {'collective':
                         {'error': 'Collective does not have quorum'}})
                return
            #TODO(jjohnson2): Cannot do the invitation if not the head node, the certificate hand-carrying
            #can't work in such a case.
            name = request['name']
            invitation = invites.create_server_invitation(name)
            tlvdata.send(connection,
                         {'collective': {'invitation': invitation}})
            connection.close()
        if 'join' == operation:
            invitation = request['invitation']
            try:
                invitation = base64.b64decode(invitation)
                name, invitation = invitation.split('@', 1)
            except Exception:
                tlvdata.send(
                    connection,
                    {'collective':
                         {'status': 'Invalid token format'}})
                connection.close()
                return
            host = request['server']
            try:
                remote = socket.create_connection((host, 13001))
                # This isn't what it looks like.  We do CERT_NONE to disable
                # openssl verification, but then use the invitation as a
                # shared secret to validate the certs as part of the join
                # operation
                remote = ssl.wrap_socket(remote,  cert_reqs=ssl.CERT_NONE,
                                         keyfile='/etc/confluent/privkey.pem',
                                         certfile='/etc/confluent/srvcert.pem')
            except Exception:
                tlvdata.send(
                    connection,
                    {'collective':
                         {'status': 'Failed to connect to {0}'.format(host)}})
                connection.close()
                return
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
            if 'error' in rsp:
                tlvdata.send(connection, {'collective':
                                              {'status': rsp['error']}})
                connection.close()
                return
            proof = rsp['collective']['approval']
            proof = base64.b64decode(proof)
            j = invites.check_server_proof(invitation, mycert, cert, proof)
            if not j:
                remote.close()
                tlvdata.send(connection, {'collective':
                                              {'status': 'Bad server token'}})
                connection.close()
                return
            tlvdata.send(connection, {'collective': {'status': 'Success'}})
            connection.close()
            currentleader = rsp['collective']['leader']
            f = open('/etc/confluent/cfg/myname', 'w')
            f.write(name)
            f.close()
            eventlet.spawn_n(connect_to_leader, rsp['collective'][
                'fingerprint'], name)
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
        myleader = get_leader(connection)
        ldrfprint = cfm.get_collective_member_by_address(
            myleader)['fingerprint']
        tlvdata.send(connection,
                     {'collective': {'approval': myrsp,
                                     'fingerprint': ldrfprint,
                                     'leader': get_leader(connection)}})
    if 'assimilate' == operation:
        drone = request['name']
        droneinfo = cfm.get_collective_member(drone)
        if not droneinfo:
            tlvdata.send(connection,
                         {'error': 'Unrecognized leader, '
                                   'redo invitation process'})
            return
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
        connection.close()
    if 'getinfo' == operation:
        drone = request['name']
        droneinfo = cfm.get_collective_member(drone)
        if not (droneinfo and util.cert_matches(droneinfo['fingerprint'],
                                                cert)):
            tlvdata.send(connection,
                         {'error': 'Invalid certificate, '
                                   'redo invitation process'})
            connection.close()
            return
        collinfo = {}
        populate_collinfo(collinfo)
        tlvdata.send(connection, collinfo)
    if 'connect' == operation:
        drone = request['name']
        droneinfo = cfm.get_collective_member(drone)
        if not (droneinfo and util.cert_matches(droneinfo['fingerprint'],
                                                cert)):
            tlvdata.send(connection,
                         {'error': 'Invalid certificate, '
                                   'redo invitation process'})
            connection.close()
            return
        myself = connection.getsockname()[0]
        if myself != get_leader(connection):
            tlvdata.send(
                connection,
                {'error': 'Cannot assimilate, our leader is '
                          'in another castle', 'leader': currentleader})
            connection.close()
            return
        if connecting.active:
            tlvdata.send(connection, {'error': 'Connecting right now',
                                      'backoff': True})
            connection.close()
            return
        if request['txcount'] > cfm._txcount:
            retire_as_leader()
            tlvdata.send(connection,
                         {'error': 'Client has higher tranasaction count, '
                                   'should assimilate me, connecting..',
                          'txcount': cfm._txcount})
            eventlet.spawn_n(connect_to_leader, None, None,
                             connection.getpeername()[0])
            connection.close()
            return
        if retrythread:
            retrythread.cancel()
            retrythread = None
        with leader_init:
            cfm.update_collective_address(request['name'],
                                          connection.getpeername()[0])
            tlvdata.send(connection, cfm._dump_keys(None, False))
            tlvdata.send(connection, cfm._cfgstore['collective'])
            tlvdata.send(connection, cfm.get_globals())
            cfgdata = cfm.ConfigManager(None)._dump_to_json()
            tlvdata.send(connection, {'txcount': cfm._txcount,
                                      'dbsize': len(cfgdata)})
            connection.sendall(cfgdata)
        #tlvdata.send(connection, {'tenants': 0}) # skip the tenants for now,
        # so far unused anyway
        if not cfm.relay_slaved_requests(drone, connection):
            if not retrythread:  # start a recovery if everyone else seems
                # to have disappeared
                retrythread = eventlet.spawn_after(30 + random.random(),
                                                   start_collective)
        # ok, we have a connecting member whose certificate checks out
        # He needs to bootstrap his configuration and subscribe it to updates


def populate_collinfo(collinfo):
    iam = get_myname()
    collinfo['leader'] = iam
    collinfo['active'] = list(cfm.cfgstreams)
    activemembers = set(cfm.cfgstreams)
    activemembers.add(iam)
    collinfo['offline'] = []
    for member in cfm.list_collective():
        if member not in activemembers:
            collinfo['offline'].append(member)


def try_assimilate(drone):
    try:
        remote = connect_to_collective(None, drone)
    except socket.error:
        # Oh well, unable to connect, hopefully the rest will be
        # in order
        return
    tlvdata.send(remote, {'collective': {'operation': 'assimilate',
                                         'name': get_myname(),
                                         'txcount': cfm._txcount}})
    tlvdata.recv(remote)  # the banner
    tlvdata.recv(remote)  # authpassed... 0..
    answer = tlvdata.recv(remote)
    if not answer:
        log.log(
            {'error':
                 'No answer from {0} while trying to assimilate'.format(
                     drone),
            'subsystem': 'collective'})
        return
    if 'txcount' in answer:
        log.log({'info': 'Deferring to {0} due to transaction count'.format(
            drone), 'subsystem': 'collective'})
        connect_to_leader(None, None, leader=remote.getpeername()[0])
        return
    if 'error' in answer:
        log.log({
            'error': 'Error encountered while attempting to '
                     'assimilate {0}: {1}'.format(drone, answer['error']),
            'subsystem': 'collective'})
        return
    log.log({'info': 'Assimilated {0} into collective'.format(drone),
             'subsystem': 'collective'})


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
    global follower
    global retrythread
    log.log({'info': 'Becoming leader of collective',
             'subsystem': 'collective'})
    if follower:
        follower.kill()
        follower = None
    if retrythread:
        retrythread.cancel()
        retrythread = None
    currentleader = connection.getsockname()[0]
    skipaddr = connection.getpeername()[0]
    myname = get_myname()
    for member in cfm.list_collective():
        dronecandidate = cfm.get_collective_member(member)['address']
        if dronecandidate in (currentleader, skipaddr) or member == myname:
            continue
        eventlet.spawn_n(try_assimilate, dronecandidate)


def startup():
    global cfginitlock
    members = list(cfm.list_collective())
    if len(members) < 2:
        # Not in collective mode, return
        return
    if cfginitlock is None:
        cfginitlock = threading.RLock()
    eventlet.spawn_n(start_collective)

def start_collective():
    global follower
    global retrythread
    if follower:
        follower.kill()
        follower = None
    try:
        if cfm.cfgstreams:
            cfm.check_quorum()
            # Do not start if we have quorum and are leader
            return
    except exc.DegradedCollective:
        pass
    if leader_init.active:  # do not start trying to connect if we are
        # xmitting data to a follower
        return
    myname = get_myname()
    for member in sorted(list(cfm.list_collective())):
        if member == myname:
            continue
        if cfm.cfgleader is None:
            cfm.stop_following(True)
        ldrcandidate = cfm.get_collective_member(member)['address']
        if connect_to_leader(name=myname, leader=ldrcandidate):
            break
    else:
        retrythread = eventlet.spawn_after(30 + random.random(),
                                           start_collective)


