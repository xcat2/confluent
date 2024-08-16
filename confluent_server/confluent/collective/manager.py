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

import asyncio
import base64
import confluent.collective.invites as invites
import confluent.config.configmanager as cfm
import confluent.exceptions as exc
import confluent.log as log
import confluent.noderange as noderange
import confluent.asynctlvdata as tlvdata
import confluent.util as util
import socket
import ssl
import confluent.sortutil as sortutil
import ctypes
import ctypes.util
import random
import time
import sys


class PyObject_HEAD(ctypes.Structure):
    _fields_ = [
        ("ob_refcnt",    ctypes.c_ssize_t),
        ("ob_type",      ctypes.c_void_p),
    ]

class PySSLContext(ctypes.Structure):
    _fields_ = [
        ("ob_base",      PyObject_HEAD),
        ("ctx",         ctypes.c_void_p),
    ]

currentleader = None
follower = None
retrythread = None
failovercheck = None
initting = True
reassimilate = None

libssl = ctypes.CDLL(ctypes.util.find_library('ssl'))
libssl.SSL_CTX_set_cert_verify_callback.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]


@ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p)
def verify_stub(store, misc):
    return 1


class ContextBool(object):
    def __init__(self):
        self.active = False
        self.mylock = asyncio.Lock()

    async def __aenter__(self):
        self.active = True
        return await self.mylock.__aenter__()

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.active = False
        return await self.mylock.__aexit__(exc_type, exc_val, exc_tb)

connecting = ContextBool()
leader_init = ContextBool()
enrolling = ContextBool()

async def connect_to_leader(cert=None, name=None, leader=None, remote=None, isretry=False):
    global currentleader
    global follower
    ocert = cert
    oname = name
    oleader = leader
    oremote = remote
    if leader is None:
        leader = currentleader
    if not isretry:
        log.log({'info': 'Attempting connection to leader {0}'.format(leader),
                 'subsystem': 'collective'})
    try:
        remote = await connect_to_collective(cert, leader, remote)
    except Exception as e:
        log.log({'error': 'Collective connection attempt to {0} failed: {1}'
                          ''.format(leader, str(e)),
                 'subsystem': 'collective'})
        return False
    async with connecting:
        async with cfm._initlock:
            # remote is a socket...
            banner = await tlvdata.recv(remote)  # the banner
            if not banner:
                return
            vers = banner.split()[2]
            if vers != b'v4':
                raise Exception('This instance only supports protocol 4, synchronize versions between collective members')
            await tlvdata.recv(remote)  # authpassed... 0..
            if name is None:
                name = get_myname()
            await tlvdata.send(remote, {'collective': {'operation': 'connect',
                                                 'name': name,
                                                 'txcount': cfm._txcount}})
            keydata = await tlvdata.recv(remote)
            if not keydata:
                return False
            if 'error' in keydata:
                if 'backoff' in keydata:
                    log.log({
                        'info': 'Collective initialization in progress on '
                                '{0}'.format(leader),
                        'subsystem': 'collective'})
                    return False
                if 'waitinline' in keydata:
                    await asyncio.sleep(0.3)
                    return await connect_to_leader(cert, name, leader, None, isretry=True)
                if 'leader' in keydata:
                    if keydata['leader'] == None:
                        return None
                    log.log(
                        {'info': 'Prospective leader {0} has redirected this '
                                 'member to {1}'.format(leader, keydata['leader']),
                         'subsystem': 'collective'})
                    ldrc = cfm.get_collective_member_by_address(
                        keydata['leader'])
                    if ldrc and ldrc['name'] == name:
                        raise Exception("Redirected to self")
                    return await connect_to_leader(name=name,
                                             leader=keydata['leader'])
                if 'txcount' in keydata:
                    log.log({'info':
                                 'Prospective leader {0} has inferior '
                                 'transaction count, becoming leader'
                                 ''.format(leader), 'subsystem': 'collective',
                             'subsystem': 'collective'})
                    return await become_leader(remote)
                return False
                follower.cancel()
                await cfm.stop_following()
                follower = None
            if follower is not None:
                follower.cancel()
                await cfm.stop_following()
                follower = None
            log.log({'info': 'Following leader {0}'.format(leader),
                     'subsystem': 'collective'})
            colldata = await tlvdata.recv(remote)
            globaldata = await tlvdata.recv(remote)
            dbi = await tlvdata.recv(remote)
            dbsize = dbi['dbsize']
            dbjson = b''
            while (len(dbjson) < dbsize):
                ndata = await remote[0].read(dbsize - len(dbjson))
                if not ndata:
                    try:
                        remote[1].close()
                        await remote[1].wait_closed()
                    except Exception:
                        pass
                    log.log({'error': 'Retrying connection, error during initial sync', 'subsystem': 'collective'})
                    return await connect_to_leader(ocert, oname, oleader, None)
                    raise Exception("Error doing initial DB transfer")  # bad ssl write retry
                dbjson += ndata
            await cfm.clear_configuration()
            try:
                cfm._restore_keys(keydata, None, sync=False)
                for c in colldata:
                    cfm._true_add_collective_member(c, colldata[c]['address'],
                                                    colldata[c]['fingerprint'],
                                                    sync=False, role=colldata[c].get('role', None))
                for globvar in globaldata:
                    cfm.set_global(globvar, globaldata[globvar], False)
                cfm._txcount = dbi.get('txcount', 0)
                await cfm.ConfigManager(tenant=None)._load_from_json(dbjson,
                                                               sync=False)
                cfm.commit_clear()
            except Exception:
                print(repr(e))
                await cfm.stop_following()
                cfm.rollback_clear()
                raise
            currentleader = leader
        #spawn this as a thread...
        #remote.settimeout(90)
        follower = util.spawn(follow_leader(remote, leader))
    return True


async def follow_leader(remote, leader):
    global currentleader
    global retrythread
    global follower
    cleanexit = False
    newleader = None
    try:
        exitcause = await cfm.follow_channel(remote)
        newleader = exitcause.get('newleader', None)
    finally:
        if cleanexit:
            log.log({'info': 'Previous following cleanly closed',
                     'subsystem': 'collective'})
            return
        if newleader:
            log.log(
                {'info': 'Previous leader directed us to join new leader {}'.format(newleader)})
            try:
                if await connect_to_leader(None, get_myname(), newleader):
                    return
            except Exception:
                log.log({'error': 'Unknown error attempting to connect to {}, check trace log'.format(newleader), 'subsystem': 'collective'})
                cfm.logException()
        log.log({'info': 'Current leader ({0}) has disappeared, restarting '
                         'collective membership'.format(leader), 'subsystem': 'collective'})
        # The leader has folded, time to startup again...
        follower = None
        await cfm.stop_following()
        currentleader = None
        if retrythread is None:  # start a recovery
            retrythread = util.spawn_after(
                random.random(), start_collective)

async def _create_tls_connection(host, port):
    cloop = asyncio.get_event_loop()
    ainfo = await cloop.getaddrinfo(
                    host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    for res in ainfo:
        af, socktype, proto, canonname, sa = res
        remote = socket.socket(af, socktype, proto)
        remote.setsockopt(
            socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        remote.settimeout(0)
        await cloop.sock_connect(remote, sa)
        break
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    ssl_ctx = PySSLContext.from_address(id(ctx)).ctx
    libssl.SSL_CTX_set_cert_verify_callback(ssl_ctx, verify_stub, 0)
    ctx.load_cert_chain('/etc/confluent/srvcert.pem', '/etc/confluent/privkey.pem')
    sreader = asyncio.StreamReader()
    sreaderprot = asyncio.StreamReaderProtocol(sreader)
    tport, _ = await cloop.create_connection(
        lambda: sreaderprot, sock=remote, ssl=ctx, server_hostname='x')
    swriter = asyncio.StreamWriter(tport, sreaderprot, sreader, cloop)
    return (sreader, swriter)


async def create_connection(member):
        remote = None
        try:
            remote = await _create_tls_connection(member, 13001)
            #remote = socket.create_connection((member, 13001), 2)
            #remote.settimeout(15)
            # TLS cert validation is custom and will not pass normal CA vetting
            # to override completely in the right place requires enormous effort, so just defer until after connect
        except Exception as e:
            return member, e
        return member, remote

async def connect_to_collective(cert, member, remote=None):
    if remote is None:
        _, remote = await create_connection(member)
        if isinstance(remote, Exception):
            raise remote
    if cert:
        fprint = cert
    else:
        collent = cfm.get_collective_member_by_address(member)
        fprint = collent['fingerprint']
    cnn = remote[1].transport.get_extra_info('ssl_object')
    if not util.cert_matches(fprint, cnn.getpeercert(binary_form=True)):
        # probably Janeway up to something
        raise Exception("Certificate mismatch in the collective")
    return remote

mycachedname = [None, 0]
def get_myname():
    if mycachedname[1] > time.time() - 15:
        return mycachedname[0]
    try:
        with open('/etc/confluent/cfg/myname', 'r') as f:
            mycachedname[0] = f.read().strip()
            mycachedname[1] = time.time()
            return mycachedname[0]
    except IOError:
        myname = socket.gethostname().split('.')[0]
        with open('/etc/confluent/cfg/myname', 'w') as f:
            f.write(myname)
        mycachedname[0] = myname
        mycachedname[1] = time.time()
        return myname

def in_collective():
    return bool(list(cfm.list_collective()))

async def handle_connection(connection, cert, request, local=False):
    global currentleader
    global retrythread
    global initting
    operation = request['operation']
    if not cert:
        if not local:
            return
        if operation in ('show', 'delete'):
            if not list(cfm.list_collective()):
                await tlvdata.send(connection,
                             {'collective': {'error': 'Collective mode not '
                                                      'enabled on this '
                                                      'system'}})
                return
            if follower is not None:
                linfo = cfm.get_collective_member_by_address(currentleader)
                try:
                    _, remote = await create_connection(currentleader)
                    if isinstance(remote, Exception):
                        raise remote
                except Exception as e:
                    print(repr(e))
                    await cfm.stop_following()
                    return
                #remote = ssl.wrap_socket(remote, cert_reqs=ssl.CERT_NONE,
                #                         keyfile='/etc/confluent/privkey.pem',
                #                         certfile='/etc/confluent/srvcert.pem')
                cert = remote[1].get_extra_info('ssl_object').getpeercert(binary_form=True)
                if not (linfo and util.cert_matches(
                        linfo['fingerprint'],
                        cert)):
                    remote[1].close()
                    await remote[1].wait_closed()
                    await tlvdata.send(connection,
                                 {'error': 'Invalid certificate, '
                                           'redo invitation process'})
                    connection[1].close()
                    await connection[1].wait_closed()
                    return
                await tlvdata.recv(remote)  # ignore banner
                await tlvdata.recv(remote)  # ignore authpassed: 0
                await tlvdata.send(remote,
                             {'collective': {'operation': 'getinfo',
                                             'name': get_myname()}})
                collinfo = await tlvdata.recv(remote)
            else:
                collinfo = {}
                populate_collinfo(collinfo)
            try:
                cfm.check_quorum()
                collinfo['quorum'] = True
            except exc.DegradedCollective:
                collinfo['quorum'] = False
            if operation == 'show':
                await tlvdata.send(connection, {'collective':  collinfo})
            elif operation == 'delete':
                todelete = request['member']
                if (todelete == collinfo['leader'] or 
                       todelete in collinfo['active']):
                    await tlvdata.send(connection, {'collective':
                            {'error': '{0} is still active, stop the confluent service to remove it'.format(todelete)}})
                    return
                if todelete not in collinfo['offline']:
                    await tlvdata.send(connection, {'collective':
                            {'error': '{0} is not a recognized collective member'.format(todelete)}})
                    return
                await cfm.del_collective_member(todelete)
                await tlvdata.send(connection,
                    {'collective': {'status': 'Successfully deleted {0}'.format(todelete)}})
                connection[1].close()
                await connection[1].wait_closed()
            return
        if 'invite' == operation:
            try:
                cfm.check_quorum()
            except exc.DegradedCollective:
                await tlvdata.send(connection,
                    {'collective':
                         {'error': 'Collective does not have quorum'}})
                return
            #TODO(jjohnson2): Cannot do the invitation if not the head node, the certificate hand-carrying
            #can't work in such a case.
            name = request['name']
            role = request.get('role', '')
            invitation = invites.create_server_invitation(name, role)
            await tlvdata.send(connection,
                         {'collective': {'invitation': invitation}})
            connection[1].close()
            await connection[1].wait_closed()
        if 'join' == operation:
            invitation = request['invitation']
            try:
                invitation = base64.b64decode(invitation)
                name, invitation = invitation.split(b'@', 1)
                name = util.stringify(name)
            except Exception:
                await tlvdata.send(
                    connection,
                    {'collective':
                         {'status': 'Invalid token format'}})
                await tlvdata.close(connection)
                return
            host = request['server']
            try:
                cloop = asyncio.get_event_loop()
                ainfo = await cloop.getaddrinfo(
                    host, 13001, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
                for res in ainfo:
                    af, socktype, proto, canonname, sa = res
                    remote = socket.socket(af, socktype, proto)
                    remote.setsockopt(
                        socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    remote.settimeout(0)
                    await cloop.sock_connect(remote, sa)
                    break
                #remote = socket.create_connection((host, 13001), 15)
                # This isn't what it looks like.  We do CERT_NONE to disable
                # openssl verification, but then use the invitation as a
                # shared secret to validate the certs as part of the join
                # operation
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                ssl_ctx = PySSLContext.from_address(id(ctx)).ctx
                libssl.SSL_CTX_set_cert_verify_callback(ssl_ctx, verify_stub, 0)
                ctx.load_cert_chain('/etc/confluent/srvcert.pem', '/etc/confluent/privkey.pem')
                sreader = asyncio.StreamReader()
                sreaderprot = asyncio.StreamReaderProtocol(sreader)
                tport, _ = await cloop.create_connection(
                    lambda: sreaderprot, sock=remote, ssl=ctx, server_hostname='x')
                swriter = asyncio.StreamWriter(tport, sreaderprot, sreader, cloop)
                remote = (sreader, swriter)
                #remote = ssl.wrap_socket(remote,  cert_reqs=ssl.CERT_NONE,
                #                         keyfile='/etc/confluent/privkey.pem',
                #                         certfile='/etc/confluent/srvcert.pem')
            except Exception:
                await tlvdata.send(
                    connection,
                    {'collective':
                         {'status': 'Failed to connect to {0}'.format(host)}})
                await tlvdata.close(connection)
                raise
                return
            mycert = util.get_certificate_from_file(
                '/etc/confluent/srvcert.pem')
            cert = tport.get_extra_info('ssl_object').getpeercert(binary_form=True)
            proof = base64.b64encode(invites.create_client_proof(
                invitation, mycert, cert))
            await tlvdata.recv(remote)  # ignore banner
            await tlvdata.recv(remote)  # ignore authpassed: 0
            await tlvdata.send(remote, {'collective': {'operation': 'enroll',
                                                 'name': name, 'hmac': proof}})
            rsp = await tlvdata.recv(remote)
            if 'error' in rsp:
                await tlvdata.send(connection, {'collective':
                                              {'status': rsp['error']}})
                return
            proof = rsp['collective']['approval']
            proof = base64.b64decode(proof)
            j = invites.check_server_proof(invitation, mycert, cert, proof)
            if not j:
                remote[1].close()
                await remote[1].wait_closed()
                await tlvdata.send(connection, {'collective':
                                              {'status': 'Bad server token'}})
                return
            await tlvdata.send(connection, {'collective': {'status': 'Success'}})
            await tlvdata.close(connection)
            currentleader = rsp['collective']['leader']
            f = open('/etc/confluent/cfg/myname', 'w')
            f.write(name)
            f.close()
            log.log({'info': 'Connecting to collective due to join',
                     'subsystem': 'collective'})
            util.spawn(connect_to_leader(rsp['collective'][
                'fingerprint'], name))
    if 'enroll' == operation:
        async with enrolling:
            cfm.check_quorum()
            mycert = util.get_certificate_from_file('/etc/confluent/srvcert.pem')
            proof = base64.b64decode(request['hmac'])
            myrsp, role = invites.check_client_proof(request['name'], mycert,
                                                     cert, proof)
            if not myrsp:
                await tlvdata.send(connection, {'error': 'Invalid token'})
                return
            if not list(cfm.list_collective()):
                # First enrollment of a collective, since the collective doesn't
                # quite exist, then set initting false to let the enrollment action
                # drive this particular initialization
                initting = False
            myrsp = base64.b64encode(myrsp)
            fprint = util.get_fingerprint(cert)
            myfprint = util.get_fingerprint(mycert)
            iam = cfm.get_collective_member(get_myname())
            if not iam:
                await cfm.add_collective_member(get_myname(),
                                          connection[1].transport.get_extra_info('socket').getsockname()[0], myfprint)
            await cfm.add_collective_member(request['name'],
                                    connection[1].transport.get_extra_info('socket').getpeername()[0], fprint, role)
            myleader = await get_leader(connection)
            ldrfprint = cfm.get_collective_member_by_address(
                myleader)['fingerprint']
            await tlvdata.send(connection,
                        {'collective': {'approval': myrsp,
                                        'fingerprint': ldrfprint,
                                        'leader': await get_leader(connection)}})
            havequorum = False
            while not havequorum:
                try:
                    cfm.check_quorum()
                    havequorum = True
                except exc.DegradedCollective:
                    await asyncio.sleep(0.1)
    if 'assimilate' == operation:
        drone = request['name']
        droneinfo = cfm.get_collective_member(drone)
        if not droneinfo:
            await tlvdata.send(connection,
                         {'error': 'Unrecognized leader, '
                                   'redo invitation process'})
            return
        if not util.cert_matches(droneinfo['fingerprint'], cert):
            await tlvdata.send(connection,
                         {'error': 'Invalid certificate, '
                                   'redo invitation process'})
            return
        if request['txcount'] < cfm._txcount:
            await tlvdata.send(connection,
                         {'error': 'Refusing to be assimilated by inferior'
                                   'transaction count',
                          'txcount': cfm._txcount,})
            return
        if cfm.cfgstreams and request['txcount'] == cfm._txcount:
            try:
                cfm.check_quorum()
                await tlvdata.send(connection,
                         {'error': 'Refusing to be assimilated as I am a leader with quorum',
                          'txcount': cfm._txcount,})
                return
            except exc.DegradedCollective:
                followcount = request.get('followcount', None)
                myfollowcount = len(list(cfm.cfgstreams))
                if followcount is not None:
                    if followcount < myfollowcount:
                        await tlvdata.send(connection,
                             {'error': 'Refusing to be assimilated by leader with fewer followers',
                            'txcount': cfm._txcount,})
                        return
                    elif followcount == myfollowcount:
                        myname = sortutil.naturalize_string(get_myname())
                        if myname < sortutil.naturalize_string(request['name']):
                            await tlvdata.send(connection,
                                {'error': 'Refusing, my name is better',
                                'txcount': cfm._txcount,})
                            return
        if follower is not None and not follower.dead:
            await tlvdata.send(
                connection,
                {'error': 'Already following, assimilate leader first',
                 'leader': currentleader})
            connection[1].close()
            await connection[1].wait_closed()
            return
        if connecting.active:
            # don't try to connect while actively already trying to connect
            await tlvdata.send(connection, {'status': 0})
            connection[1].close()
            await connection[1].wait_closed()
            return
        cnn = connection[1].get_extra_info('socket')
        if (currentleader == cnn.getpeername()[0] and
                follower and not follower.dead):
            # if we are happily following this leader already, don't stir
            # the pot
            await tlvdata.send(connection, {'status': 0})
            connection[1].close()
            await connection[1].wait_closed()
            return
        log.log({'info': 'Connecting in response to assimilation',
                 'subsystem': 'collective'})
        newleader = cnn.getpeername()[0]
        if cfm.cfgstreams:
            await retire_as_leader(newleader)
        await tlvdata.send(connection, {'status': 0})
        connection[1].close()
        await connection[1].wait_closed()
        if not await connect_to_leader(None, None, leader=newleader):
            if retrythread is None:
                retrythread = util.spawn_after(random.random(),
                                                   start_collective)
    if 'getinfo' == operation:
        drone = request['name']
        droneinfo = cfm.get_collective_member(drone)
        if not (droneinfo and util.cert_matches(droneinfo['fingerprint'],
                                                cert)):
            await tlvdata.send(connection,
                         {'error': 'Invalid certificate, '
                                   'redo invitation process'})
            connection[1].close()
            await connection[1].wait_closed()
            return
        collinfo = {}
        populate_collinfo(collinfo)
        await tlvdata.send(connection, collinfo)
    if 'connect' == operation:
        drone = request['name']
        droneinfo = cfm.get_collective_member(drone)
        if not (droneinfo and util.cert_matches(droneinfo['fingerprint'],
                                                cert)):
            await tlvdata.send(connection,
                         {'error': 'Invalid certificate, '
                                   'redo invitation process'})
            connection[1].close()
            await connection[1].wait_closed()
            return
        cnn = connection[1].transport.get_extra_info('socket')
        myself = cnn.getsockname()[0]
        if connecting.active or initting:
            await tlvdata.send(connection, {'error': 'Connecting right now',
                                      'backoff': True})
            connection[1].close()
            await connection[1].wait_closed()
            return
        if leader_init.active:
            print("initting leader....")
            await tlvdata.send(connection, {'error': 'Servicing a connection',
                                      'waitinline': True})
            connection[1].close()
            await connection[1].wait_closed()
            return
        if myself != await get_leader(connection):
            await tlvdata.send(
                connection,
                {'error': 'Cannot assimilate, our leader is '
                          'in another castle', 'leader': currentleader})
            connection[1].close()
            await connection[1].wait_closed()
            return
        if request['txcount'] > cfm._txcount:
            await retire_as_leader()
            await tlvdata.send(connection,
                         {'error': 'Client has higher tranasaction count, '
                                   'should assimilate me, connecting..',
                          'txcount': cfm._txcount})
            log.log({'info': 'Connecting to leader due to superior '
                             'transaction count', 'subsystem': 'collective'})
            cnn = connection[1].transport.get_extra_info('socket')
            peername = cnn.getpeername()[0]
            connection[1].close()
            await connection[1].wait_closed()
            if not await connect_to_leader(
                None, None, peername):
                if retrythread is None:
                    retrythread = util.spawn_after(5 + random.random(),
                                                   start_collective)
            return
        if retrythread is not None:
            retrythread.cancel()
            retrythread = None
        async with leader_init:
            cnn = connection[1].get_extra_info('socket')
            cfm.update_collective_address(request['name'],
                                          cnn.getpeername()[0])
            await tlvdata.send(connection, cfm._dump_keys(None, False))
            await tlvdata.send(connection, cfm._cfgstore['collective'])
            await tlvdata.send(connection, {'confluent_uuid': cfm.get_global('confluent_uuid')}) # cfm.get_globals())
            cfgdata = await cfm.ConfigManager(None)._dump_to_json()
            try:
                await tlvdata.send(connection, {'txcount': cfm._txcount,
                                'dbsize': len(cfgdata)})
                connection[1].write(cfgdata)
                await connection[1].drain()
            except Exception as e:
                print(repr(e))
                try:
                    connection[1].close()
                    await connection[1].wait_closed()
                finally:
                    raise
                    return None
        #tlvdata.send(connection, {'tenants': 0}) # skip the tenants for now,
        # so far unused anyway
        #connection.settimeout(90)
        if not await cfm.relay_slaved_requests(drone, connection):
            log.log({'info': 'All clients have disconnected, starting recovery process',
                     'subsystem': 'collective'})
            if retrythread is None:  # start a recovery if everyone else seems
                # to have disappeared
                retrythread = util.spawn_after(5 + random.random(),
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
    collinfo['nonvoting'] = []
    for member in cfm.list_collective():
        if member not in activemembers:
            collinfo['offline'].append(member)
        if cfm.get_collective_member(member).get('role', None) == 'nonvoting':
            collinfo['nonvoting'].append(member)


async def try_assimilate(drone, followcount, remote):
    global retrythread
    try:
        remote = await connect_to_collective(None, drone, remote)
    except socket.error:
        # Oh well, unable to connect, hopefully the rest will be
        # in order
        return
    await tlvdata.send(remote, {'collective': {'operation': 'assimilate',
                                         'name': get_myname(),
                                         'followcount': followcount,
                                         'txcount': cfm._txcount}})
    await tlvdata.recv(remote)  # the banner
    await tlvdata.recv(remote)  # authpassed... 0..
    answer = await tlvdata.recv(remote)
    if not answer:
        log.log(
            {'error':
                 'No answer from {0} while trying to assimilate'.format(
                     drone),
            'subsystem': 'collective'})
        return True
    if 'txcount' in answer:
        log.log({'info': 'Deferring to {0} due to target being a better leader'.format(
            drone), 'subsystem': 'collective'})
        await retire_as_leader(drone)
        cnn = remote[1].transport.get_extra_info('socket')
        if not await connect_to_leader(None, None, leader=cnn.getpeername()[0]):
            if retrythread is None:
                retrythread = util.spawn_after(random.random(),
                                                    start_collective)
        return False
    if 'leader' in answer:
        # Will wait for leader to see about assimilation
        return True
    if 'error' in answer:
        log.log({
            'error': 'Error encountered while attempting to '
                     'assimilate {0}: {1}'.format(drone, answer['error']),
            'subsystem': 'collective'})
        return True
    log.log({'info': 'Assimilated {0} into collective'.format(drone),
             'subsystem': 'collective'})
    return True


async def get_leader(connection):
    cnn = connection[1].transport.get_extra_info('socket')
    if currentleader is None or cnn.getpeername()[0] == currentleader:
        # cancel retry if a retry is pending
        if currentleader is None:
            msg = 'Becoming leader as no leader known'
        else:
            msg = 'Becoming leader because {0} attempted to connect and it ' \
                  'is current leader'.format(currentleader)
        log.log({'info': msg, 'subsystem': 'collective'})
        await become_leader(connection)
    return currentleader

async def retire_as_leader(newleader=None):
    global currentleader
    global reassimilate
    await cfm.stop_leading(newleader)
    if reassimilate is not None:
        reassimilate.cancel()
        reassimilate = None
    currentleader = None

async def become_leader(connection):
    global currentleader
    global follower
    global retrythread
    global reassimilate
    if cfm.get_collective_member(get_myname()).get('role', None) == 'nonvoting':
        log.log({'info': 'Refraining from being leader of collective (nonvoting)',
            'subsystem': 'collective'})
        return False
    log.log({'info': 'Becoming leader of collective',
             'subsystem': 'collective'})
    if follower is not None:
        follower.cancel()
        await cfm.stop_following()
        follower = None
    if retrythread is not None:
        retrythread.cancel()
        retrythread = None
    cnn = connection[1].transport.get_extra_info('socket')
    currentleader = cnn.getsockname()[0]
    skipaddr = cnn.getpeername()[0]
    if reassimilate is not None:
        reassimilate.cancel()
    reassimilate = util.spawn(reassimilate_missing())
    cfm._ready = True
    if await _assimilate_missing(skipaddr):
        schedule_rebalance()


async def reassimilate_missing():
    await asyncio.sleep(30)
    while True:
        try:
            await _assimilate_missing()
        except Exception as e:
            cfm.logException()
        await asyncio.sleep(30)

async def _assimilate_missing(skipaddr=None):
    connecto = []
    myname = get_myname()
    skipem = set(cfm.cfgstreams)
    numfollowers = len(skipem)
    skipem.add(currentleader)
    if skipaddr is not None:
        skipem.add(skipaddr)
    for member in cfm.list_collective():
        dronecandidate = cfm.get_collective_member(member)['address']
        if dronecandidate in skipem or member == myname or member in skipem:
            continue
        connecto.append(dronecandidate)
    if not connecto:
        return True
    connections = []
    for ct in connecto:
        connections.append(util.spawn(create_connection(ct)))
    for ent in connections:
        ent = await ent
        member, remote = ent
        if isinstance(remote, Exception):
            continue
        if not await try_assimilate(member, numfollowers, remote):
            return False
    return True


def startup():
    members = list(cfm.list_collective())
    if len(members) < 2:
        # Not in collective mode, return
        return
    util.spawn(start_collective())

async def check_managers():
    global failovercheck
    if not follower:
        try:
            cfm.check_quorum()
        except exc.DegradedCollective:
            failovercheck = None
            return
        c = cfm.ConfigManager(None)
        collinfo = {}
        populate_collinfo(collinfo)
        availmanagers = {}
        offlinemgrs = set(collinfo['offline'])
        offlinemgrs.add('')
        for offline in collinfo['offline']:
            nodes = noderange.NodeRange(
                'collective.manager=={}'.format(offline), c).nodes
            managercandidates = c.get_node_attributes(
                nodes, 'collective.managercandidates')
            expandednoderanges = {}
            for node in nodes:
                if node not in managercandidates:
                    continue
                targets = managercandidates[node].get('collective.managercandidates', {}).get('value', None)
                if not targets:
                    continue
                if not availmanagers:
                    for active in collinfo['active']:
                        availmanagers[active] = len(
                            noderange.NodeRange(
                                'collective.manager=={}'.format(active), c).nodes)
                    availmanagers[collinfo['leader']] = len(
                            noderange.NodeRange(
                                'collective.manager=={}'.format(
                                    collinfo['leader']), c).nodes)
                if targets not in expandednoderanges:
                    expandednoderanges[targets] = set(
                        noderange.NodeRange(targets, c).nodes) - offlinemgrs
                targets = sorted(expandednoderanges[targets], key=availmanagers.get)
                if not targets:
                    continue
                c.set_node_attributes({node: {'collective.manager': {'value': targets[0]}}})
                availmanagers[targets[0]] += 1
        await _assimilate_missing()
    failovercheck = None

def schedule_rebalance():
    global failovercheck
    if not failovercheck:
        failovercheck = True
        failovercheck = util.spawn_after(10, check_managers)

async def start_collective():
    global follower
    global retrythread
    global initting
    initting = True
    retrythread = None
    try:
        cfm.membership_callback = schedule_rebalance
        if follower is not None:
            initting = False
            return
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
        connecto = []
        for member in sorted(list(cfm.list_collective())):
            if member == myname:
                continue
            if cfm.get_collective_member(member).get('role', None) == 'nonvoting':
                continue
            if cfm.cfgleader is None:
                await cfm.stop_following(True)
            ldrcandidate = cfm.get_collective_member(member)['address']
            connecto.append(ldrcandidate)
        connections = []
        for ct in connecto:
            connections.append(util.spawn(create_connection(ct)))
        pnding = connections
        while pnding:
            rdy, pnding = await asyncio.wait(pnding, return_when=asyncio.FIRST_COMPLETED)
            for ent in rdy:
                member, remote = await ent
                if isinstance(remote, Exception):
                    continue
                if follower is None:
                    log.log({'info': 'Performing startup attempt to {0}'.format(
                        member), 'subsystem': 'collective'})
                    if not await connect_to_leader(name=myname, leader=member, remote=remote):
                        remote[1].close()
                        await remote[1].wait_closed()
                else:
                    remote[1].close()
                    await remote[1].wait_closed()
    except Exception as e:
        pass
    finally:
        if retrythread is None and follower is None:
            #retrythread = asyncio.create_task(start_collective())
            retrythread = util.spawn_after(5 + random.random(),
                                               start_collective)
        initting = False
