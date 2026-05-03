# Copyright 2013 IBM Corporation
# Copyright 2015-2017 Lenovo
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

"""This represents the low layer message framing portion of IPMI"""

import collections
import hashlib
import hmac
import operator
import os
import random
import select
import socket
import struct
#import threading
import asyncio

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers import modes

import aiohmi.exceptions as exc
from aiohmi.ipmi.private import constants
from aiohmi.ipmi.private import util
from aiohmi.ipmi.private.util import _monotonic_time
from aiohmi.ipmi.private.util import get_ipmi_error


KEEPALIVE_SESSIONS = asyncio.Lock()
WAITING_SESSIONS = asyncio.Lock()


try:
    dict.iteritems

    def dictitems(d):
        return d.iteritems()
except AttributeError:
    def dictitems(d):
        return d.items()

# minimum timeout for first packet to retry in any given
# session.  This will be randomized to stagger out retries
# in case of congestion
initialtimeout = 0.5
# the thread in which all IO will be performed
# This thread tucks away the threading situation such that
# calling code doesn't have to do any gymnastics.
iothread = None
# whether io thread is yet ready to work
iothreadready = False
# threads waiting for iothreadready
iothreadwaiters = []
ioqueue = collections.deque([])
myself = None
ipv6support = None
selectdeadline = 0
running = True
# set of iosockets that will be shared amongst Session objects
iosockets = []
# no more than this many BMCs will share a socket
# this could be adjusted based on rmem_max
# value, leading to fewer filehandles
MAX_BMCS_PER_SOCKET = 64

# maximum time to allow idle, more than this and BMC may assume
MAX_IDLE = 29
# incorrect idle


def unmatched(response, netfn, cmd):
    if not response:
        return True
    return response['command'] != cmd or response['netfn'] != netfn

sockwatching = True

async def terminate():
    global sockwatching
    await Session._cleanup()
    sockwatching = False
    iosockets[0].sendto(
                b'\x01', (myself, iosockets[0].getsockname()[1]))

def sock_completion(cloop, currsock, fut):
    cloop.remove_reader(currsock)
    fut.set_result(None)

async def watchsockets():
    global sockwatching
    sockwatching = True
    global iothreadready
    global selectdeadline
    iowaiters = []
    directediowaiters = {}
    timeout = 300
    iothreadready = True
    while iothreadwaiters:
        waiter = iothreadwaiters.pop()
        waiter.set()
    while sockwatching:
        if timeout < 0:
            timeout = 0
        selectdeadline = _monotonic_time() + timeout
        currfutures = []
        for currsock in iosockets:
            currfut = asyncio.Future()
            asyncio.get_event_loop().add_reader(currsock, sock_completion, asyncio.get_event_loop(), currsock, currfut)
            currfutures.append(currfut)
        #select.select(iosockets, (), (), timeout)
        done, futures = await asyncio.wait(currfutures, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
        for currfut in done:
            await currfut
        # pessimistically move out the deadline
        # doing it this early (before ioqueue is evaluated)
        # this avoids other threads making a bad assumption
        # about not having to break into the select
        selectdeadline = _monotonic_time() + 300
        timeout = 300
        sockaddrs = _io_graball(iosockets, directediowaiters)
        for w in iowaiters:
            w[1].set()
        iowaiters = []
        for d in list(directediowaiters):
            # these are the existing waiters that didn't get
            # satisfied last graball, allow them to set a new
            # deadline if they still have time waiting, or
            # if they have expired, wake them now to let them
            # process their timeout
            rightnow = _monotonic_time()
            for idx, w in reversed(list(
                    enumerate(directediowaiters[d]))):
                ltimeout = w[0] - rightnow
                if ltimeout < 0:
                    w[1].set()  # time is up, wake the caller
                    del directediowaiters[d][idx]
                elif ltimeout < timeout:
                    timeout = ltimeout
            if not directediowaiters[d]:
                del directediowaiters[d]
        while ioqueue:
            workitem = ioqueue.popleft()
            # order: function, args, list to append to , event to set
            if workitem[2] is None and sockaddrs:
                workitem[1].set()
            elif workitem[2] in sockaddrs:
                workitem[1].set()
            else:
                ltimeout = workitem[0] - _monotonic_time()
                if ltimeout < timeout:
                    timeout = ltimeout
                if workitem[2] is None:
                    iowaiters.append(workitem)
                else:
                    if workitem[2] in directediowaiters:
                        directediowaiters[workitem[2]].append(workitem)
                    else:
                        directediowaiters[workitem[2]] = [workitem]




sessionqueue = collections.deque([])


async def _io_wait(timeout, myaddr=None, evq=None):
    evt = asyncio.Event()
    if evq is not None:
        evq.append(evt)
    deadline = timeout + _monotonic_time()
    ioqueue.append((deadline, evt, myaddr))
    if deadline < selectdeadline:
        iosockets[0].sendto(b'\x01', (myself, iosockets[0].getsockname()[1]))
    await evt.wait()


def _io_sendto(mysocket, packet, sockaddr):
    mysocket.setblocking(1)
    try:
        mysocket.sendto(packet, sockaddr)
    except Exception:
        pass


def _io_graball(mysockets, iowaiters):
    sockaddrs = []
    for mysocket in mysockets:
        while True:
            rdata = _io_recvfrom(mysocket, 3000)
            if rdata is None:
                break
            # If the payload is shorter than 4 bytes, it cannot
            # be a useful packet.  Skip it entirely.
            # This applies to the packet sent to self to break
            # into the select
            if len(rdata[0]) < 4:
                continue
            myport = mysocket.getsockname()[1]
            rdata = rdata + (mysocket,)
            relsession = None
            if (rdata[1] in Session.bmc_handlers
                    and myport in Session.bmc_handlers[rdata[1]]):
                # session data
                rdata = rdata + (True,)
                relsession = Session.bmc_handlers[rdata[1]][myport]
            elif rdata[2] in Session.bmc_handlers:
                # aiohmi is the bmc, and we have sessionless data
                rdata = rdata + (False,)
                relsession = Session.bmc_handlers[rdata[2]][0]
            if relsession is not None:
                relsession.pktqueue.append(rdata)
                sessionqueue.append(relsession)
            if rdata[1] in iowaiters:
                for w in iowaiters[rdata[1]]:
                    w[1].set()
                del iowaiters[rdata[1]]
            sockaddrs.append(rdata[1])
    return sockaddrs


def _io_recvfrom(mysocket, size):
    mysocket.setblocking(0)
    try:
        return mysocket.recvfrom(size)
    except socket.error:
        return None


try:
    IPPROTO_IPV6 = socket.IPPROTO_IPV6
except AttributeError:
    IPPROTO_IPV6 = 41  # This is the Win32 version of IPPROTO_IPV6, the only
    # platform where python *doesn't* have this in socket that aiohmi is
    # targetting.


async def _poller(timeout=0):
    if sessionqueue:
        return True
    await _io_wait(timeout)
    return sessionqueue


def _aespad(data):
    """ipmi demands a certain pad scheme, per table 13-20 AES-CBC encrypted

    payload fields.
    """
    currlen = len(data) + 1  # need to count the pad length field as well
    neededpad = currlen % 16
    if neededpad:  # if it happens to be zero, hurray, but otherwise invert the
        # sense of the padding
        neededpad = 16 - neededpad
    padval = 1
    pad = bytearray(neededpad)
    while padval <= neededpad:
        pad[padval - 1] = padval
        padval += 1
    pad.append(neededpad)
    return pad


def _checksum(*data):  # Two's complement over the data
    csum = sum(data)
    csum ^= 0xff
    csum += 1
    csum &= 0xff
    return csum


class Session(object):
    """A class to manage common IPMI session logistics

    Almost all developers should not worry about this class and instead be
    looking toward ipmi.Command and ipmi.Console.

    For those that do have to worry, the main interesting thing is that the
    event loop can go one of two ways.  Either a larger manager can query using
    class methods
    the soonest timeout deadline and the filehandles to poll and assume
    responsibility for the polling, or it can register filehandles to be
    watched.  This is primarily of interest to Console class, which may have an
    input filehandle to watch and can pass it to Session.

    :param bmc: hostname or ip address of the BMC
    :param userid: username to use to connect
    :param password: password to connect to the BMC
    :param kg: optional parameter if BMC requires Kg be set
    :param port: UDP port to communicate with, pretty much always 623
    :param onlogon: callback to receive notification of login completion
    """
    bmc_handlers = {}
    waiting_sessions = {}
    initting_sessions = {}
    keepalive_sessions = {}
    peeraddr_to_nodes = {}
    iterwaiters = []
    # NOTE(jbjohnso):
    # socketpool is a mapping of sockets to usage count
    socketpool = {}
    # this will be a lock.  Delay the assignment so that a calling framework
    # can do something like reassign our threading and select modules
    socketchecking = None

    # Maintain single Cryptography backend for all IPMI sessions (seems to be
    # thread-safe)
    _crypto_backend = default_backend()

    @classmethod
    async def _cleanup(cls):
        for sesskey in list(cls.bmc_handlers):
            for portent in list(cls.bmc_handlers[sesskey]):
                session = cls.bmc_handlers[sesskey][portent]
                session.cleaningup = True
                await session.logout(False)

    @classmethod
    async def _assignsocket(cls, server=None, forbiddensockets=()):
        global iothread
        global iothreadready
        global iosockets
        global ipv6support
        global myself

        # seek for the least used socket.  As sessions close, they may free
        # up slots in seemingly 'full' sockets.  This scheme allows those
        # slots to be recycled
        sorted_candidates = None
        if server is None:
            sorted_candidates = sorted(dictitems(cls.socketpool),
                                       key=operator.itemgetter(1))
        if sorted_candidates is None:
            sorted_candidates = []
        for candidate in sorted_candidates:
            if candidate[1] >= MAX_BMCS_PER_SOCKET:
                break
            if candidate[0] in forbiddensockets:
                continue
            cls.socketpool[candidate[0]] += 1
            return candidate[0]
        # we need a new socket
        if server:
            # Regardless of whether ipv6 is supported or not, we
            # must try to honor the address format of the given
            # server, rather than trying to create an automatic one
            tmpsocket = socket.socket(server[0], socket.SOCK_DGRAM)
            if server[0] == socket.AF_INET6:
                tmpsocket.setsockopt(IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        elif ipv6support:
            tmpsocket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            tmpsocket.setsockopt(IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        elif ipv6support is None:  # we need to determine ipv6 support now
            try:
                tmpsocket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                tmpsocket.setsockopt(IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                ipv6support = True
            except socket.error:
                ipv6support = False
                myself = '127.0.0.1'
                tmpsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            tmpsocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            tmpsocket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16777216)
        except Exception:
            pass        
        if server is None:
            # Rather than wait until send() to bind, bind now so that we have
            # a port number allocated no matter what
            tmpsocket.bind(('', 0))
            cls.socketpool[tmpsocket] = 1
        else:
            tmpsocket.bind(server[4])
        iosockets.append(tmpsocket)
        if myself is None:
            # we have confirmed kernel IPv6 support, but ::1 may still not
            # be there
            try:
                iosockets[0].sendto(
                    b'\x01', ('::1', iosockets[0].getsockname()[1]))
                myself = '::1'
            except socket.error:
                # AF_INET6, but no '::1', try the AF_INET6 version of 127
                myself = '::ffff:127.0.0.1'
        if iothread is None:
            initevt = asyncio.Event()
            iothreadwaiters.append(initevt)
            iothread = asyncio.get_event_loop().create_task(watchsockets())
            await initevt.wait()
        elif not iothreadready:
            initevt = asyncio.Event()
            iothreadwaiters.append(initevt)
            await initevt.wait()
        return tmpsocket

    def _sync_login(self, response):
        """Handle synchronous callers in lieu of a client-provided callback"""
        # Be a stub, the __init__ will catch and respond to ensure response
        # is given in the same thread as was called
        return

    @classmethod
    async def _is_session_valid(cls, session):
        await KEEPALIVE_SESSIONS.acquire()
        try:
            sess = cls.keepalive_sessions.get(session, None)
            if sess is not None and 'timeout' in sess:
                if sess['timeout'] < _monotonic_time() - 15:
                    # session would have timed out by now, don't use it
                    return False
        finally:
            KEEPALIVE_SESSIONS.release()
        return not session.broken

    async def __new__(cls,
                bmc,
                userid,
                password,
                port=623,
                kg=None,
                privlevel=None,
                keepalive=True):
        trueself = None
        forbidsock = []
        for res in socket.getaddrinfo(bmc, port, 0, socket.SOCK_DGRAM):
            sockaddr = res[4]
            if ipv6support and res[0] == socket.AF_INET:
                # convert the sockaddr to AF_INET6
                newhost = '::ffff:' + sockaddr[0]
                sockaddr = (newhost, sockaddr[1], 0, 0)
            if sockaddr in cls.bmc_handlers:
                for portself in list(dictitems(cls.bmc_handlers[sockaddr])):
                    self = portself[1]
                    if not ((self.logged or self.logging)
                            and await cls._is_session_valid(self)):
                        # we have encountered a leftover broken session
                        del cls.bmc_handlers[sockaddr][portself[0]]
                        continue
                    if (self.bmc == bmc
                            and self.userid == userid
                            and self.password == password
                            and self.kgo == kg):
                        trueself = self
                        break
                    # ok, the candidate seems to be working, but does not match
                    # will need to allow creation of a new session, but
                    # must forbid use of this socket so that the socket
                    # share routing code does not get confused.
                    # in principle, should be able to distinguish by session
                    # id, however it's easier this way
                    forbidsock.append(self.socket)
            if trueself:
                return trueself
            i = cls.initting_sessions.get(
                (bmc, userid, password, port, kg), False)
            if i:
                i.initialized = True
                i.logging = True
                return i
            self = super().__new__(cls)
            self.forbidsock = forbidsock
            await self.__init__(
                bmc, userid, password, port, kg, privlevel, keepalive)
            cls.initting_sessions[(bmc, userid, password, port, kg)] = self
            return self

    async def __init__(self,
                 bmc,
                 userid,
                 password,
                 port=623,
                 kg=None,
                 privlevel=None,
                 keepalive=True):
        if hasattr(self, 'initialized'):
            # new found an existing session, do not corrupt it
            while self.logging and not self.broken:
                await Session.wait_for_rsp()
        self.awaitingresponse = False
        self.lastresponse = None
        self.atomicop = asyncio.Lock()
        self.broken = False
        self.socket = None
        self.logged = 0
        if privlevel is not None:
            self.privlevel = privlevel
            self.autopriv = False
        else:
            self.privlevel = 4
            self.autopriv = True
        self.onlogpayload = None
        self.onlogpayloadtype = None
        self.logoutexpiry = None
        self.autokeepalive = keepalive
        self.maxtimeout = 2  # be aggressive about giving up on initial packet
        self.incommand = False
        self.nameonly = 16  # default to name only lookups in RAKP exchange
        self.servermode = False
        self.initialized = True
        self.cleaningup = False
        self.lastpayload = None
        self._customkeepalives = None
        # queue of events denoting line to run a cmd
        self.evq = collections.deque([])
        self.bmc = bmc
        # a private queue for packets for which this session handler
        # is destined to receive
        self.pktqueue = collections.deque([])

        try:
            self.userid = userid.encode('utf-8')
            self.password = password.encode('utf-8')
        except AttributeError:
            self.userid = userid
            self.password = password
        self.nowait = False
        self.pendingpayloads = collections.deque([])
        self.request_entry = []
        self.kgo = kg
        if kg is not None:
            try:
                kg = kg.encode('utf-8')
            except AttributeError:
                pass
            self.kg = kg
        else:
            self.kg = self.password
        self.port = port
        self.async_ = False
        self.logonwaiters = [self._sync_login]
        if self.__class__.socketchecking is None:
            self.__class__.socketchecking = asyncio.Lock()
        await self.socketchecking.acquire()
        try:
            self.socket = await self._assignsocket(forbiddensockets=self.forbidsock)
        finally:
            self.socketchecking.release()
        await self.login()
        if not self.async_:
            while self.logging:
                await Session.wait_for_rsp()
        if self.broken:
            raise exc.IpmiException(self.errormsg)

    async def _mark_broken(self, error=None):
        # since our connection has failed retries
        # deregister our keepalive facility
        self.lastpayload = None
        self.onlogpayload = None
        await KEEPALIVE_SESSIONS.acquire()
        try:
            Session.keepalive_sessions.pop(self, None)
        finally:
            KEEPALIVE_SESSIONS.release()
        await WAITING_SESSIONS.acquire()
        try:
            Session.waiting_sessions.pop(self, None)
        finally:
            WAITING_SESSIONS.release()
        try:
            del Session.initting_sessions[(self.bmc, self.userid,
                                           self.password, self.port,
                                           self.kgo)]
        except KeyError:
            pass
        await self.logout(False)
        # self.logging = False
        self.errormsg = error
        if not self.broken:
            self.broken = True
            if self.socket:
                self.socketpool[self.socket] -= 1
        while self.logonwaiters:
            waiter = self.logonwaiters.pop()
            try:
                waiter({'error': 'Session failed to initialize'})
            except Exception:
                pass

    async def onlogon(self, parameter):
        if 'error' in parameter:
            while self.logonwaiters:
                waiter = self.logonwaiters.pop()
                waiter(parameter)
            await self._mark_broken(parameter['error'])
        elif self.onlogpayload:
            await self._cmdwait()
            payload = self.onlogpayload
            payload_type = self.onlogpayloadtype
            self.incommand = _monotonic_time() + self._getmaxtimeout()
            self.onlogpayload = None
            await self.send_payload(payload, payload_type)
        while self.logonwaiters:
            waiter = self.logonwaiters.pop()
            waiter(parameter)

    def _initsession(self):
        # NOTE(jbjohnso): this number can be whatever we want.
        #                 I picked 'xCAT' minus 1 so that a hexdump of packet
        #                 would show xCAT
        self.localsid = 2017673555
        self.remseqnumber = None
        self.confalgo = 0
        self.aeskey = None
        self.integrityalgo = 0
        self.attemptedhash = 256
        self.currhashlib = None
        self.currhashlen = 0
        self.k1 = None
        self.rmcptag = 1
        self.lastpayload = None
        self.ipmicallback = None
        self.sessioncontext = None
        self.sequencenumber = 0
        self.sessionid = 0
        self.authtype = 0
        self.ipmiversion = 1.5
        self.timeout = initialtimeout + (0.5 * random.random())
        self.logoutexpiry = _monotonic_time() + self._getmaxtimeout()
        self.rqlun = 0
        self.seqlun = 0
        # NOTE(jbjohnso): per IPMI table 5-4, software ids in the ipmi spec may
        #                 be 0x81 through 0x8d.  We'll stick with 0x81 for now,
        #                 do not forsee a reason to adjust
        self.rqaddr = 0x81

        self.logging = True
        self.logged = 0
        # NOTE(jbjohnso): when we confirm a working sockaddr, put it here to
        #                 skip getaddrinfo
        self.sockaddr = None
        # NOTE(jbjohnso): this tracks netfn,command,seqlun combinations that
        #                 were retried so that we don't loop around and reuse
        #                 the same request data and cause potential ambiguity
        #                 in return
        self.tabooseq = {}
        # NOTE(jbjohnso): default to supporting ipmi 2.0.  Strictly by spec,
        #                 this should gracefully be backwards compat, but some
        #                 1.5 implementations checked reserved bits
        self.ipmi15only = 0
        self.sol_handler = None
        # NOTE(jbjohnso): This is the callback handler for any SOL payload

    def _make_bridge_request_msg(self, channel, netfn, command):
        """This function generate message for bridge request. It is a

        part of ipmi payload.
        """
        # NOTE(puwen): need to pay attention for this function because the
        # structure does not seem to match the specifications.
        head = bytearray((constants.IPMI_BMC_ADDRESS,
                          constants.netfn_codes['application'] << 2))
        check_sum = _checksum(*head)
        # NOTE(fengqian): according IPMI Figure 14-11, rqSWID is set to 81h
        boday = bytearray((0x81, (self.seqlun << 2) | self.rqlun,
                           constants.IPMI_SEND_MESSAGE_CMD, 0x40 | channel))
        # NOTE(fengqian): Track request
        self._add_request_entry((constants.netfn_codes['application'] + 1,
                                 self.seqlun, constants.IPMI_SEND_MESSAGE_CMD))
        return head + bytearray((check_sum,)) + boday

    def _add_request_entry(self, entry=()):
        """This function record the request with netfn, sequence number and

        command, which will be used in parse_ipmi_payload.
        :param entry: a set of netfn, sequence number and command.
        """
        if not self._lookup_request_entry(entry):
            self.request_entry.append(entry)

    def _lookup_request_entry(self, entry=()):
        return entry in self.request_entry

    def _remove_request_entry(self, entry=()):
        if self._lookup_request_entry(entry):
            self.request_entry.remove(entry)

    def _make_ipmi_payload(self, netfn, command, bridge_request=None, data=(),
                           rslun=0):
        """This function generates the core ipmi payload that would be

        applicable for any channel (including KCS)
        """
        bridge_msg = []
        self.expectedcmd = command
        # in ipmi, the response netfn is always one
        self.expectednetfn = netfn + 1
        # higher than the request payload, we assume
        # we are always the requestor for now
        seqincrement = 7  # IPMI spec forbids gaps bigger then 7 in seq number.
        # Risk the taboo rather than violate the rules
        while (not self.servermode
               and (netfn, command, self.seqlun) in self.tabooseq
               and self.tabooseq[(netfn, command, self.seqlun)]
               and seqincrement):
            self.tabooseq[(self.expectednetfn, command, self.seqlun)] -= 1
            # Allow taboo to eventually expire after a few rounds
            self.seqlun += 1  # the last two bits are lun, so add 4 to add 1
            self.seqlun &= 0x3f  # we only have one byte, wrap when exceeded
            seqincrement -= 1

        if bridge_request:
            addr = bridge_request.get('addr', 0x0)
            channel = bridge_request.get('channel', 0x0)
            bridge_msg = self._make_bridge_request_msg(channel, netfn, command)
            # NOTE(fengqian): For bridge request, rsaddr is specified and
            # rqaddr is BMC address.
            rqaddr = constants.IPMI_BMC_ADDRESS
            rsaddr = addr
        else:
            rqaddr = self.rqaddr
            rsaddr = constants.IPMI_BMC_ADDRESS
        if self.servermode:
            rsaddr = self.clientaddr
        # figure 13-4, first two bytes are rsaddr and
        # netfn, for non-bridge request, rsaddr is always 0x20 since we are
        # addressing BMC while rsaddr is specified forbridge request
        header = bytearray((rsaddr, (netfn << 2) | rslun))
        reqbody = bytearray(
            (rqaddr, (self.seqlun << 2) | self.rqlun, command)) + data
        headsum = bytearray((_checksum(*header),))
        bodysum = bytearray((_checksum(*reqbody),))
        payload = header + headsum + reqbody + bodysum
        if bridge_request:
            payload = bridge_msg + payload
            # NOTE(fengqian): For bridge request, another check sum is needed.
            tail_csum = _checksum(*payload[3:])
            payload.append(tail_csum)

        if not self.servermode:
            self._add_request_entry((self.expectednetfn, self.seqlun, command))
        return payload

    async def _generic_callback(self, response):
        errorstr = get_ipmi_error(response)
        if errorstr:
            response['error'] = errorstr
        self.lastresponse = response

    def _isincommand(self):
        if self.incommand:
            stillin = self.incommand - _monotonic_time()
            if stillin > 0:
                return stillin
            else:
                self.lastpayload = None
        return 0

    def _getmaxtimeout(self):
        cumulativetime = 0
        incrementtime = self.timeout
        while incrementtime < self.maxtimeout:
            cumulativetime += incrementtime
            incrementtime += 1
        return (cumulativetime + 1) * (self.logontries + 1)

    async def _cmdwait(self):
        while self._isincommand():
            await _io_wait(self._isincommand(), self.sockaddr, self.evq)

    async def awaitresponse(self, retry, netfn, command):
        self.awaitingresponse = True
        try:
            alltimeout = _monotonic_time() + (self._getmaxtimeout() * 2)
            while (retry and unmatched(self.lastresponse, netfn, command)
                    and (self.logging or self.logged or self.onlogpayload)):
                timeout = self.expiration - _monotonic_time()
                await _io_wait(timeout, self.sockaddr)
                while self.iterwaiters:
                    waiter = self.iterwaiters.pop()
                    waiter({'success': True})
                await self.process_pktqueue()
                if _monotonic_time() > alltimeout:
                    await self._mark_broken()
                    raise exc.IpmiException('Session no longer connected')
                await WAITING_SESSIONS.acquire()
                try:
                    if (self in self.waiting_sessions
                            and self.expiration < _monotonic_time()):
                        self.waiting_sessions.pop(self, None)
                        if not self.lastpayload and not self.logging:
                            return
                        await self._timedout()
                finally:
                    WAITING_SESSIONS.release()
        finally:
            self.awaitingresponse = False



    async def raw_command(self,
                    netfn,
                    command,
                    bridge_request=None,
                    data=(),
                    retry=True,
                    timeout=None,
                    callback=None,
                    rslun=0):
        while (self.logging and not self.logged
                and _monotonic_time() < self.logoutexpiry):
            await self.pause(1)
        if not self.logged:
            if (self.logoutexpiry is not None
                    and _monotonic_time() > self.logoutexpiry):
                await self._mark_broken()
            raise exc.IpmiException('Session no longer connected')
        await self.atomicop.acquire()
        try:
            await self._cmdwait()
            if not self.logged:
                raise exc.IpmiException('Session no longer connected')
            self.incommand = _monotonic_time() + self._getmaxtimeout()
        finally:
            self.atomicop.release()
        self.lastresponse = None
        if callback is None:
            self.ipmicallback = self._generic_callback
        else:
            self.ipmicallback = callback
        await self._send_ipmi_net_payload(netfn, command, data,
                                    bridge_request=bridge_request,
                                    retry=retry,
                                    timeout=timeout, rslun=rslun)

        if retry:  # in retry case, let the retry timers indicate wait time
            timeout = None
        else:  # if not retry, give it a second before surrending
            timeout = 1
        if callback:
            # caller *must* clean up self.incommand and self.evq
            return
        # The event loop is shared amongst aiohmi session instances
        # within a process.  In this way, synchronous usage of the interface
        # plays well with asynchronous use.  In fact, this produces the
        # behavior of only the constructor needing a callback.  From then on,
        # synchronous usage of the class acts in a greenthread style governed
        # by order of data on the network
        await self.awaitresponse(retry, netfn + 1, command)
        lastresponse = self.lastresponse
        self.lastresponse = None
        self.incommand = False
        while self.evq:
            self.evq.popleft().set()
        if retry and lastresponse is None:
            raise exc.IpmiException('Session no longer connected')
        return lastresponse

    async def _send_ipmi_net_payload(self, netfn=None, command=None, data=(), code=0,
                               bridge_request=None,
                               retry=None, timeout=None,
                               rslun=0):
        if retry is None:
            retry = not self.servermode
        if self.servermode:
            data = bytearray((code,)) + bytearray(data)
            if netfn is None:
                netfn = self.clientnetfn
            if command is None:
                command = self.clientcommand
        else:
            data = bytearray(data)
        ipmipayload = self._make_ipmi_payload(netfn, command, bridge_request,
                                              data, rslun)
        payload_type = constants.payload_types['ipmi']
        await self.send_payload(payload=ipmipayload, payload_type=payload_type,
                                retry=retry, timeout=timeout)

    async def send_payload(self, payload=(), payload_type=None, retry=True,
                     needskeepalive=False, timeout=None):
        """Send payload over the IPMI Session

        :param needskeepalive: If the payload is expected not to count as
                               'active' by the BMC, set this to True
                               to avoid Session considering the
                               job done because of this payload.
                               Notably, 0-length SOL packets
                               are prone to confusion.
        :param timeout: Specify a custom timeout for long-running request
        """
        if payload and self.lastpayload:
            # we already have a packet outgoing, make this
            # a pending payload
            # this way a simplistic BMC won't get confused
            # and we also avoid having to do more complicated
            # retry mechanism where each payload is
            # retried separately
            self.pendingpayloads.append((payload, payload_type, retry))
            return
        if payload_type is None:
            payload_type = self.last_payload_type
        if not payload:
            payload = self.lastpayload
        message = bytearray(b'\x06\x00\xff\x07')  # constant IPMI RMCP header
        if retry:
            self.lastpayload = payload
            self.last_payload_type = payload_type
        if not isinstance(payload, bytearray):
            payload = bytearray(payload)
        message.append(self.authtype)
        baretype = payload_type
        if self.integrityalgo:
            payload_type |= 0b01000000
        if self.confalgo:
            payload_type |= 0b10000000
        if self.ipmiversion == 2.0:
            message.append(payload_type)
            if baretype == 2:
                # TODO(jbjohnso): OEM payload types
                raise NotImplementedError("OEM Payloads")
            elif baretype not in constants.payload_types.values():
                raise NotImplementedError(
                    "Unrecognized payload type %d" % baretype)
            message += struct.pack("<I", self.sessionid)
        message += struct.pack("<I", self.sequencenumber)
        if self.ipmiversion == 1.5:
            message += struct.pack("<I", self.sessionid)
            if not self.authtype == 0:
                message += self._ipmi15authcode(payload)
            message.append(len(payload))
            message += payload
            # Guessing the ipmi spec means the whole
            totlen = 34 + len(message)
            # packet and assume no tag in old 1.5 world
            if totlen in (56, 84, 112, 128, 156):
                message.append(0)  # Legacy pad as mandated by ipmi spec
        elif self.ipmiversion == 2.0:
            psize = len(payload)
            if self.confalgo:
                pad = (psize + 1) % 16  # pad has to cope with one byte
                # field like the _aespad function
                if pad:  # if no pad needed, then we take no more action
                    pad = 16 - pad
                # new payload size grew according to pad
                newpsize = psize + pad + 17
                # size, plus pad length, plus 16 byte IV
                # (Table 13-20)
                message.append(newpsize & 0xff)
                message.append(newpsize >> 8)
                iv = os.urandom(16)
                message += iv
                payloadtocrypt = bytes(payload + _aespad(payload))
                crypter = Cipher(
                    algorithm=algorithms.AES(self.aeskey),
                    mode=modes.CBC(iv),
                    backend=self._crypto_backend
                )
                encryptor = crypter.encryptor()
                message += encryptor.update(payloadtocrypt
                                            ) + encryptor.finalize()
            else:  # no confidetiality algorithm
                message.append(psize & 0xff)
                message.append(psize >> 8)
                message += payload
            if self.integrityalgo:  # see table 13-8,
                # RMCP+ packet format
                # TODO(jbjohnso): SHA256 which is now
                # allowed
                neededpad = (len(message) - 2) % 4
                if neededpad:
                    neededpad = 4 - neededpad
                message += b'\xff' * neededpad
                message.append(neededpad)
                message.append(7)  # reserved, 7 is the required value for the
                # specification followed
                message += hmac.new(
                    self.k1, bytes(message[4:]),
                    self.currhashlib).digest()[:self.currhashlen]
                # per RFC2404 truncates to 96 bits
        self.netpacket = message
        # advance idle timer since we don't need keepalive while sending
        # packets out naturally
        await KEEPALIVE_SESSIONS.acquire()
        try:
            if (self in Session.keepalive_sessions and not needskeepalive
                    and not self._customkeepalives):
                Session.keepalive_sessions[self]['timeout'] = \
                    _monotonic_time() + MAX_IDLE - (random.random() * 4.9)
            await self._xmit_packet(retry, timeout=timeout)
        finally:
            KEEPALIVE_SESSIONS.release()

    def _ipmi15authcode(self, payload, checkremotecode=False):
        # checkremotecode is used to verify remote code,
        # otherwise this function is used to general authcode for local
        if self.authtype == 0:
            # Only for things before auth in ipmi 1.5, not
            # like 2.0 cipher suite 0
            return ()
        password = self.password
        padneeded = 16 - len(password)
        if padneeded < 0:
            raise exc.IpmiException("Password is too long for ipmi 1.5")
        password += '\x00' * padneeded
        if checkremotecode:
            seqbytes = struct.pack("<I", self.remseqnumber)
        else:
            seqbytes = struct.pack("<I", self.sequencenumber)
        sessdata = struct.pack("<I", self.sessionid)
        bodydata = password + sessdata + payload + seqbytes + password
        dgst = hashlib.md5(bodydata).digest()
        return dgst

    async def _got_channel_auth_cap(self, response):
        if 'error' in response:
            await self.onlogon(response)
            return
        if response['code'] == 0xcc and self.ipmi15only is not None:
            # tried ipmi 2.0 against a 1.5 which should work, but some bmcs
            # thought 'reserved' meant 'must be zero'
            self.ipmi15only = 1
            return self._get_channel_auth_cap()
        mysuffix = " while trying to get channel authentication capabalities"
        errstr = get_ipmi_error(response, suffix=mysuffix)
        if errstr:
            self.onlogon({'error': errstr})
            return
        data = response['data']
        self.currentchannel = data[0]
        if data[1] & 0b10000000 and data[3] & 0b10:  # ipmi 2.0 support
            self.ipmiversion = 2.0
        if self.ipmiversion == 1.5:
            if not (data[1] & 0b100):
                self.onlogon(
                    {'error':
                     "MD5 required but not enabled/available on target BMC"})
                return
            await self._get_session_challenge()
        elif self.ipmiversion == 2.0:
            await self._open_rmcpplus_request()

    def _got_session_challenge(self, response):
        errstr = get_ipmi_error(response,
                                suffix=" while getting session challenge")
        if errstr:
            self.onlogon({'error': errstr})
            return
        data = response['data']
        self.sessionid = struct.unpack("<I", bytes(data[0:4]))[0]
        self.authtype = 2
        self._activate_session(data[4:])

    # NOTE(jbjohnso):
    # This sends the activate session payload.  We pick '1' as the requested
    # sequence number without perturbing our real sequence number

    async def _activate_session(self, data):
        rqdata = [2, 4] + list(data) + [1, 0, 0, 0]
        # TODO(jbjohnso): this always requests admin level (1.5)
        self.ipmicallback = self._activated_session
        await self._send_ipmi_net_payload(netfn=0x6, command=0x3a, data=rqdata)

    async def _activated_session(self, response):
        errstr = get_ipmi_error(response)
        if errstr:
            self.onlogon({'error': errstr})
            return
        data = response['data']
        self.sessionid = struct.unpack("<I", bytes(data[1:5]))[0]
        self.sequencenumber = struct.unpack("<I", bytes(data[5:9]))[0]
        await self._req_priv_level()

    async def _req_priv_level(self):
        self.logged = 1
        self.maxtimeout = 4  # Switch quickly to the relogin recovery
        self.logontries = 1  # have one relogin waiting to heal
        response = await self.raw_command(netfn=0x6, command=0x3b,
                                    data=[self.privlevel])
        if response['code']:
            if response['code'] in (0x80, 0x81) and self.privlevel == 4:
                # some implementations will let us get this far,
                # but suddenly get skiddish.  Try again in such a case
                self.privlevel = 3
                response = self.raw_command(netfn=0x6, command=0x3b,
                                            data=[self.privlevel])
            if response['code']:
                self.logged = 0
                self.onlogpayload = None
                self.logging = False
                self.logoutexpiry = None

                mysuffix = " while requesting privelege level %d for %s" % (
                    self.privlevel, self.userid)
                errstr = get_ipmi_error(response, suffix=mysuffix)
                if errstr:
                    self.onlogon({'error': errstr})
                    return
        self.logging = False
        self.logoutexpiry = None
        await KEEPALIVE_SESSIONS.acquire()
        try:
            Session.keepalive_sessions[self] = {}
            Session.keepalive_sessions[self]['ipmisession'] = self
            Session.keepalive_sessions[self]['timeout'] = _monotonic_time() + \
                MAX_IDLE - (random.random() * 4.9)
        finally:
            KEEPALIVE_SESSIONS.release()
        await self.onlogon({'success': True})

    async def _get_session_challenge(self):
        reqdata = bytearray([2])
        if len(self.userid) > 16:
            raise exc.IpmiException(
                "Username too long for IPMI, must not exceed 16")
        padneeded = 16 - len(self.userid)
        userid = self.userid + ('\x00' * padneeded)
        reqdata += userid
        self.ipmicallback = self._got_session_challenge
        await self._send_ipmi_net_payload(netfn=0x6, command=0x39, data=reqdata)

    async def _open_rmcpplus_request(self):
        self.authtype = 6
        # have unique local session ids to ignore aborted
        # login attempts from the past
        self.localsid += 1
        self.rmcptag += 1
        data = bytearray([
            self.rmcptag,
            0,  # request as much privilege as the channel will give us
            0, 0,  # reserved
        ])
        data += struct.pack("<I", self.localsid)
        # auth 3 sha256
        # integrity... 4 = sha256
        if self.attemptedhash == 1:
            data += bytearray([
                0, 0, 0, 8, 1, 0, 0, 0,  # table 13-17, SHA-1
                1, 0, 0, 8, 1, 0, 0, 0,  # SHA-1 integrity
                2, 0, 0, 8, 1, 0, 0, 0,  # AES privacy
                # 2,0,0,8,0,0,0,0, #no privacy confalgo
            ])
            self.currhashlib = hashlib.sha1
            self.currhashlen = 12
        else:
            data += bytearray([
                0, 0, 0, 8, 3, 0, 0, 0,  # table 13-17, SHA-256
                1, 0, 0, 8, 4, 0, 0, 0,  # SHA-256-128 integrity
                2, 0, 0, 8, 1, 0, 0, 0,  # AES privacy
                # 2,0,0,8,0,0,0,0, #no privacy confalgo
            ])
            self.currhashlib = hashlib.sha256
            self.currhashlen = 16
        self.sessioncontext = 'OPENSESSION'
        self.lastpayload = None
        await self.send_payload(
            payload=data,
            payload_type=constants.payload_types['rmcpplusopenreq'])

    async def _get_channel_auth_cap(self):
        self.ipmicallback = self._got_channel_auth_cap
        if self.ipmi15only:
            await self._send_ipmi_net_payload(netfn=0x6,
                                        command=0x38,
                                        data=[0x0e, self.privlevel])
        else:
            await self._send_ipmi_net_payload(netfn=0x6,
                                        command=0x38,
                                        data=[0x8e, self.privlevel])

    async def login(self):
        self.logontries = 1
        self._initsession()
        await self._get_channel_auth_cap()

    @classmethod
    async def pause(cls, timeout):
        try:
            starttime = _monotonic_time()
            while _monotonic_time() - starttime < timeout:
                await cls.wait_for_rsp(timeout - (_monotonic_time() - starttime))
        except Exception as e:
            print(repr(e))

    @classmethod
    async def wait_for_rsp(cls, timeout=None, callout=True):
        """IPMI Session Event loop iteration

        This watches for any activity on IPMI handles and handles registered
        by register_handle_callback.  Callers are satisfied in the order that
        packets return from network, not in the order of calling.

        :param timeout: Maximum time to wait for data to come across.  If
                        unspecified, will autodetect based on earliest timeout
        """
        global iosockets
        # Assume:
        # Instance A sends request to packet B
        # Then Instance C sends request to BMC D
        # BMC D was faster, so data comes back before BMC B
        # Instance C gets to go ahead of Instance A, because
        # Instance C can get work done, but instance A cannot

        curtime = _monotonic_time()
        # There ar a number of parties that each has their own timeout
        # The caller can specify a deadline in timeout argument
        # each session with active outbound payload has callback to
        # handle retry/timout error
        # each session that is 'alive' wants to send a keepalive ever so often.
        # We want to make sure the most strict request is honored and block for
        # no more time than that, so that whatever part(ies) need to service in
        # a deadline, will be honored
        if timeout != 0:
            await WAITING_SESSIONS.acquire()
            try:
                for session, parms in dictitems(cls.waiting_sessions):
                    if parms['timeout'] <= curtime:
                        timeout = 0  # exit after one guaranteed pass
                        break
                    if (timeout is not None
                            and timeout < parms['timeout'] - curtime):
                        continue  # timeout smaller than the current session
                        # needs
                    timeout = parms['timeout'] - curtime  # set new timeout
                    # value
            finally:
                WAITING_SESSIONS.release()
            await KEEPALIVE_SESSIONS.acquire()
            try:
                for session, parms in dictitems(cls.keepalive_sessions):
                    if parms['timeout'] <= curtime:
                        timeout = 0
                        break
                    if (timeout is not None
                            and timeout < parms['timeout'] - curtime):
                        continue
                    timeout = parms['timeout'] - curtime
            finally:
                KEEPALIVE_SESSIONS.release()
        # If the loop above found no sessions wanting *and* the caller had no
        # timeout, exit function. In this case there is no way a session
        # could be waiting so we can always return 0
        while cls.iterwaiters:
            waiter = cls.iterwaiters.pop()
            waiter({'success': True})
            # cause a quick exit from the event loop iteration for calling code
            # to be able to reasonably set up for the next iteration before
            # a long select comes along
            if timeout is not None:
                timeout = 0
        if timeout is None:
            return 0
        if await _poller(timeout=timeout):
            while sessionqueue:
                relsession = sessionqueue.popleft()
                await relsession.process_pktqueue()
        sessionstodel = []
        sessionstokeepalive = []
        await KEEPALIVE_SESSIONS.acquire()
        try:
            for session, parms in dictitems(cls.keepalive_sessions):
                # if the session is busy inside a command, defer invoking
                # keepalive until incommand is no longer the case
                if parms['timeout'] < curtime and not session._isincommand():
                    cls.keepalive_sessions[session]['timeout'] = \
                        _monotonic_time() + MAX_IDLE - (random.random() * 4.9)
                    sessionstokeepalive.append(session)
        finally:
            KEEPALIVE_SESSIONS.release()
        for session in sessionstokeepalive:
            await session._keepalive()
        await WAITING_SESSIONS.acquire()
        try:
            for session, parms in dictitems(cls.waiting_sessions):
                if parms['timeout'] < curtime:  # timeout has expired, time to
                    # give up on it and trigger timeout
                    # response in the respective session
                    # defer deletion until after loop
                    sessionstodel.append(session)
                    # to avoid confusing the for loop
            for session in sessionstodel:
                cls.waiting_sessions.pop(session, None)
            # one loop iteration to make sure recursion doesn't induce
            # redundant timeouts
        finally:
            WAITING_SESSIONS.release()
        for session in sessionstodel:
            await session._timedout()
        return len(cls.waiting_sessions)


    def register_keepalive(self, cmd, callback):
        """Register  custom keepalive IPMI command

        This is mostly intended for use by the console code.
        calling code would have an easier time just scheduling in their
        own threading scheme.  Such a behavior would naturally cause
        the default keepalive to not occur anyway if the calling code
        is at least as aggressive about timing as aiohmi
        :param cmd: A dict of arguments to be passed into raw_command
        :param callback: A function to be called with results of the keepalive

        :returns: value to identify registration for unregister_keepalive
        """
        regid = random.random()
        if self._customkeepalives is None:
            self._customkeepalives = {regid: (cmd, callback)}
        else:
            while regid in self._customkeepalives:
                regid = random.random()
            self._customkeepalives[regid] = (cmd, callback)
        return regid

    def unregister_keepalive(self, regid):
        if self._customkeepalives is None:
            return
        try:
            del self._customkeepalives[regid]
        except KeyError:
            pass

    def _keepalive_wrapper(self, callback):
        # generates a wrapped keepalive to cleanup session state
        # and call callback if appropriate
        async def _keptalive(response):
            await self._generic_callback(response)
            response = self.lastresponse
            self.lastresponse = None
            self.incommand = False
            while self.evq:
                self.evq.popleft().set()
            if callback:
                await callback(response)

        return _keptalive

    async def _keepalive(self):
        """Performs a keepalive to avoid idle disconnect"""
        if self.awaitingresponse:
            return
        try:
            keptalive = False
            if self._customkeepalives:
                kaids = list(self._customkeepalives.keys())
                for keepalive in kaids:
                    try:
                        cmd, callback = self._customkeepalives[keepalive]
                    except TypeError:
                        # raw_command made customkeepalives None
                        break
                    except KeyError:
                        # raw command ultimately caused a keepalive to
                        # deregister
                        continue
                    if callable(cmd):
                        await cmd()
                        continue
                    keptalive = True
                    cmd['callback'] = self._keepalive_wrapper(callback)
                    await self.raw_command(**cmd)
            if not keptalive:
                if self.incommand:
                    # if currently in command, no cause to keepalive
                    return
                if self.autokeepalive:
                    await self.raw_command(netfn=6, command=1,
                                           callback=self._keepalive_wrapper(None))
                else:
                    await self.logout()
        except exc.IpmiException:
            await self._mark_broken()

    async def process_pktqueue(self):
        while self.pktqueue:
            pkt = list(self.pktqueue.popleft())
            pkt[0] = bytearray(pkt[0])
            if not (pkt[0][0] == 6 and pkt[0][2:4] == b'\xff\x07'):
                continue
            # this should be in specific context, no need to check port
            # since recvfrom result was already routed to this object
            # specifically
            if pkt[1] in self.bmc_handlers:
                await self._handle_ipmi_packet(pkt[0], sockaddr=pkt[1], qent=pkt)
            elif pkt[2] in self.bmc_handlers:
                self.sessionless_data(pkt[0], pkt[1])

    async def _handle_ipmi_packet(self, data, sockaddr=None, qent=None):
        if self.sockaddr is None and sockaddr is not None:
            self.sockaddr = sockaddr
        elif (self.sockaddr is not None
              and sockaddr is not None
              and self.sockaddr != sockaddr):
            return  # here, we might have sent an ipv4 and ipv6 packet to kick
            # things off ignore the second reply since we have one
            # satisfactory answer
        if data[4] in (0, 2):  # This is an ipmi 1.5 paylod
            remseqnumber = struct.unpack('<I', bytes(data[5:9]))[0]
            remsessid = struct.unpack("<I", bytes(data[9:13]))[0]
            if (remseqnumber == 0 and remsessid == 0
                    and qent[2] in Session.bmc_handlers):
                # So a new ipmi client happens to get a previously seen and
                # still active UDP source port.  Clear ourselves out and punt
                # to IpmiServer
                del Session.bmc_handlers[sockaddr]
                iserver = Session.bmc_handlers[qent[2]][0]
                iserver.pktqueue.append(qent)
                await iserver.process_pktqueue()
                return
            if (hasattr(self, 'remseqnumber') and self.remseqnumber is not None
                    and remseqnumber < self.remseqnumber):
                return -5  # remote sequence number is too low, reject it
            self.remseqnumber = remseqnumber
            if data[4] != self.authtype:
                # BMC responded with mismatch authtype, for
                # mutual authentication reject it. If this causes
                # legitimate issues, it's the vendor's fault
                return -2

            if remsessid != self.sessionid:
                return -1  # does not match our session id, drop it
            authcode = False
            if data[4] == 2:  # we have authcode in this ipmi 1.5 packet
                authcode = data[13:29]
                del data[13:29]
                # this is why we needed a mutable representation
            payload = data[14:14 + data[13]]
            if authcode:
                expectedauthcode = self._ipmi15authcode(payload,
                                                        checkremotecode=True)
                if expectedauthcode != authcode:
                    return
            await self._parse_ipmi_payload(payload)
        elif data[4] == 6:
            await self._handle_ipmi2_packet(data)
        else:
            return  # unrecognized data, assume evil

    async def _got_rakp1(self, data):
        # stub, client sessions ignore rakp2
        pass

    async def _got_rakp3(self, data):
        # stub, client sessions ignore rakp3
        pass

    async def _got_rmcp_openrequest(self, data):
        pass

    async def _handle_ipmi2_packet(self, data):
        ptype = data[5] & 0b00111111
        # the first 16 bytes are header information as can be seen in 13-8 that
        # we will toss out
        if ptype == 0x10:
            return await self._got_rmcp_openrequest(data[16:])
        elif ptype == 0x11:  # rmcp+ response
            return await self._got_rmcp_response(data[16:])
        elif ptype == 0x12:
            return await self._got_rakp1(data[16:])
        elif ptype == 0x13:
            return await self._got_rakp2(data[16:])
        elif ptype == 0x14:
            return await self._got_rakp3(data[16:])
        elif ptype == 0x15:
            return await self._got_rakp4(data[16:])
        elif ptype == 0 or ptype == 1:  # good old ipmi payload or sol
            # If endorsing a shared secret scheme, then at the very least it
            # needs to do mutual assurance
            if not (data[5] & 0b01000000):  # This would be the line that might
                # trip up some insecure BMC
                # implementation
                return
            encrypted = 0
            if data[5] & 0b10000000:
                encrypted = 1
            authcode = data[-self.currhashlen:]
            if self.k1 is None:  # we are in no shape to process a packet now
                return
            expectedauthcode = hmac.new(
                self.k1, data[4:-self.currhashlen],
                self.currhashlib).digest()[:self.currhashlen]
            if authcode != expectedauthcode:
                return  # BMC failed to assure integrity to us, drop it
            sid = struct.unpack("<I", bytes(data[6:10]))[0]
            if sid != self.localsid:  # session id mismatch, drop it
                return
            remseqnumber = struct.unpack("<I", bytes(data[10:14]))[0]
            if (hasattr(self, 'remseqnumber') and self.remseqnumber is not None
                    and (remseqnumber < self.remseqnumber)
                    and (self.remseqnumber != 0xffffffff)):
                return
            self.remseqnumber = remseqnumber
            psize = data[14] + (data[15] << 8)
            payload = data[16:16 + psize]
            if encrypted:
                iv = data[16:32]
                crypter = Cipher(
                    algorithm=algorithms.AES(self.aeskey),
                    mode=modes.CBC(bytes(iv)),
                    backend=self._crypto_backend
                )
                decryptor = crypter.decryptor()
                payload = bytearray(decryptor.update(bytes(payload[16:])
                                                     ) + decryptor.finalize())
                padsize = payload[-1] + 1
                payload = payload[:-padsize]
            if ptype == 0:
                await self._parse_ipmi_payload(payload)
            elif ptype == 1:  # There should be no other option
                if (payload[1] & 0b1111) and self.last_payload_type == 1:
                    # for ptype 1, the 4 least significant bits of 2nd byte
                    # is  the ACK number.
                    # if it isn't an ACK at all, we'll keep retrying, however
                    # if it's a subtle SOL situation (partial ACK, wrong ACK)
                    # then sol_handler will have to resubmit and we will
                    # stop the generic retry behavior here
                    self.lastpayload = None
                    self.last_payload_type = None
                    await WAITING_SESSIONS.acquire()
                    try:
                        Session.waiting_sessions.pop(self, None)
                    finally:
                        WAITING_SESSIONS.release()
                    if len(self.pendingpayloads) > 0:
                        (nextpayload, nextpayloadtype, retry) = \
                            self.pendingpayloads.popleft()
                        await self.send_payload(payload=nextpayload,
                                          payload_type=nextpayloadtype,
                                          retry=retry)
                if self.sol_handler:
                    await self.sol_handler(payload)

    async def _got_rmcp_response(self, data):
        # see RMCP+ open session response table
        if not (self.sessioncontext and self.sessioncontext != "ESTABLISHED"):
            return -9
            # ignore payload as we are not in a state valid it
        if data[0] != self.rmcptag:
            return -9  # use rmcp tag to track and reject stale responses
        if data[1] != 0:  # response code...
            if self.attemptedhash == 256:
                self.attemptedhash = 1
                await self._open_rmcpplus_request()
                return
            if data[1] in constants.rmcp_codes:
                errstr = constants.rmcp_codes[data[1]]
            else:
                errstr = "Unrecognized RMCP code %d" % data[1]
            self.onlogon({'error': errstr})
            return -9
        self.allowedpriv = data[2]
        # NOTE(jbjohnso): At this point, the BMC has no idea about what user
        # shall be used.  As such, the allowedpriv field is actually
        # not particularly useful.  got_rakp2 is a good place to
        # gracefully detect and downgrade privilege for retry
        localsid = struct.unpack("<I", bytes(data[4:8]))[0]
        if self.localsid != localsid:
            return -9
        self.pendingsessionid = struct.unpack("<I", bytes(data[8:12]))[0]
        # TODO(jbjohnso): currently, we take it for granted that the responder
        # accepted our integrity/auth/confidentiality proposal
        self.lastpayload = None
        await self._send_rakp1()

    async def _send_rakp1(self):
        self.rmcptag += 1
        self.randombytes = os.urandom(16)
        userlen = len(self.userid)
        payload = bytearray([self.rmcptag, 0, 0, 0]) + \
            struct.pack("<I", self.pendingsessionid) + \
            self.randombytes +\
            bytearray([self.nameonly | self.privlevel, 0, 0, userlen]) + \
            self.userid
        self.sessioncontext = "EXPECTINGRAKP2"
        await self.send_payload(
            payload=payload, payload_type=constants.payload_types['rakp1'])

    async def _got_rakp2(self, data):
        if not (self.sessioncontext in ('EXPECTINGRAKP2', 'EXPECTINGRAKP4')):
            # if we are not expecting rakp2, ignore. In a retry
            # scenario, replying from stale RAKP2 after sending
            # RAKP3 seems to be best
            return -9
        if data[0] != self.rmcptag:  # ignore mismatched tags for retry logic
            return -9
        if data[1] != 0:  # if not successful, consider next move
            if data[1] in (9, 0xd) and self.privlevel == 4 and self.autopriv:
                # Here the situation is likely that the peer didn't want
                # us to use admin.  Degrade to operator and try again
                self.privlevel = 3
                await self.login()
                return
            # invalid sessionid 99% of the time means a retry
            # scenario invalidated an in-flight transaction
            if data[1] == 2:
                return
            if data[1] in constants.rmcp_codes:
                errstr = constants.rmcp_codes[data[1]]
            else:
                errstr = "Unrecognized RMCP code %d" % data[1]
            await self.onlogon({'error': errstr + " in RAKP2"})
            return -9
        localsid = struct.unpack("<I", bytes(data[4:8]))[0]
        if localsid != self.localsid:
            return -9  # discard mismatch in the session identifier
        self.remoterandombytes = bytes(data[8:24])
        self.remoteguid = bytes(data[24:40])
        userlen = len(self.userid)
        hmacdata = (struct.pack("<II", localsid, self.pendingsessionid)
                    + self.randombytes + self.remoterandombytes
                    + self.remoteguid + struct.pack(
                    "2B", self.nameonly | self.privlevel, userlen)
                    + self.userid)
        try:
            expectedhash = hmac.new(self.password, hmacdata,
                                    self.currhashlib).digest()
        except TypeError:
            print('Password for {0} is somehow malformed'.format(self.bmc))
            return -9
        hashlen = len(expectedhash)
        givenhash = struct.pack("%dB" % hashlen, *data[40:hashlen + 40])
        if givenhash != expectedhash:
            self.sessioncontext = "FAILED"
            self.onlogon({'error': "Incorrect password provided"})
            return -9
        # We have now validated that the BMC and client agree on password, time
        # to store the keys
        self.sik = hmac.new(self.kg,
                            self.randombytes + self.remoterandombytes
                            + struct.pack(
                                "2B", self.nameonly | self.privlevel, userlen)
                            + self.userid, self.currhashlib).digest()
        self.k1 = hmac.new(self.sik, b'\x01' * 20, self.currhashlib).digest()
        self.k2 = hmac.new(self.sik, b'\x02' * 20, self.currhashlib).digest()
        self.aeskey = self.k2[0:16]
        self.sessioncontext = "EXPECTINGRAKP4"
        self.lastpayload = None
        await self._send_rakp3()

    async def _send_rakp3(self):  # rakp message 3
        self.rmcptag += 1
        # rmcptag, then status 0, then two reserved 0s
        payload = [self.rmcptag, 0, 0, 0] +\
            list(struct.unpack("4B", struct.pack("<I", self.pendingsessionid)))
        hmacdata = self.remoterandombytes +\
            struct.pack("<I", self.localsid) +\
            struct.pack("2B", self.nameonly | self.privlevel,
                        len(self.userid)) +\
            self.userid

        authcode = hmac.new(self.password, hmacdata, self.currhashlib).digest()
        payload += list(struct.unpack("%dB" % len(authcode), authcode))
        await self.send_payload(
            payload=payload, payload_type=constants.payload_types['rakp3'])

    async def _relog(self):
        self.logging = True
        self._initsession()
        self.logontries -= 1
        return await self._get_channel_auth_cap()

    async def _got_rakp4(self, data):
        if self.sessioncontext != "EXPECTINGRAKP4" or data[0] != self.rmcptag:
            return -9
        if data[1] != 0:
            if data[1] == 2 and self.logontries:  # if we retried RAKP3 because
                # RAKP4 got dropped, BMC can consider it done and we must
                # restart
                self._relog()
                return
            # ignore 15 value if we are retrying.
            # xCAT did but I can't recall why exactly
            if data[1] == 15 and self.logontries:
                # TODO(jbjohnso) jog my memory to update the comment
                return
            if data[1] in constants.rmcp_codes:
                errstr = constants.rmcp_codes[data[1]]
            else:
                errstr = "Unrecognized RMCP code %d" % data[1]
            await self.onlogon({'error': errstr + " reported in RAKP4"})
            return -9
        localsid = struct.unpack("<I", bytes(data[4:8]))[0]
        if localsid != self.localsid:  # ignore if wrong session id indicated
            return -9
        hmacdata = self.randombytes +\
            struct.pack("<I", self.pendingsessionid) +\
            self.remoteguid
        expectedauthcode = hmac.new(
            self.sik, hmacdata, self.currhashlib).digest()[:self.currhashlen]
        aclen = len(expectedauthcode)
        authcode = struct.pack("%dB" % aclen, *data[8:aclen + 8])
        if authcode != expectedauthcode:
            self.onlogon({'error': "Invalid RAKP4 integrity code (wrong Kg?)"})
            return
        self.sessionid = self.pendingsessionid
        self.integrityalgo = self.attemptedhash
        self.confalgo = 'aes'
        self.sequencenumber = 1
        self.sessioncontext = 'ESTABLISHED'
        self.lastpayload = None
        await self._req_priv_level()

    # Internal function to parse IPMI nugget once extracted from its framing
    async def _parse_ipmi_payload(self, payload):
        # For now, skip the checksums since we are in LAN only,
        # TODO(jbjohnso): if implementing other channels, add checksum checks
        # here
        if len(payload) < 7:
            # This cannot possibly be a valid IPMI packet.  Note this is after
            # the integrity checks, so this must be a buggy BMC packet
            # One example was a BMC that if receiving an SOL deactivate
            # from another party would emit what looks to be an attempt
            # at SOL deactivation payload, but with the wrong payload type
            # since we can't do anything remotely sane with such a packet,
            # drop it and carry about our business.
            return
        if self.servermode:
            self.seqlun = payload[4] >> 2
            self.clientaddr = payload[3]
            self.clientnetfn = (payload[1] >> 2) + 1
            self.rqlun = payload[4] & 0b11
            self.clientcommand = payload[5]
            await self._parse_payload(payload)
            return
        # payload[4] is rqSeq + rsLUN, we only need the rqSeq
        entry = (payload[1] >> 2, payload[4] >> 2, payload[5])
        if self._lookup_request_entry(entry):
            self._remove_request_entry(entry)

            # NOTE(fengqian): for bridge request, we need to handle the
            # response twice. First response shows if message send correctly,
            # second response is the real response.
            # If the message is send crrectly, we will discard the first
            # response or else error message will be parsed and return.
            if ((entry[0] in [0x06, 0x07]) and (entry[2] == 0x34)
                    and (payload[-2] == 0x0)):
                return -1
            else:
                await self._parse_payload(payload)
                # NOTE(fengqian): recheck if the certain entry is removed in
                # case that bridge request failed.
                if self.request_entry:
                    self._remove_request_entry((self.expectednetfn,
                                                self.seqlun, self.expectedcmd))
        else:
            # payload is not a match for our last packet
            # it is also not a bridge request.
            return -1

    async def _parse_payload(self, payload):
        if hasattr(self, 'hasretried') and self.hasretried:
            self.hasretried = 0
            # try to skip it for at most 16 cycles of overflow
            self.tabooseq[
                (self.expectednetfn, self.expectedcmd, self.seqlun)] = 16
        # We want to now remember that we do not have an expected packet
        # bigger than one byte means it can never match the one byte value
        # by mistake
        self.expectednetfn = 0x1ff
        self.expectedcmd = 0x1ff
        if not self.servermode:
            self.seqlun += 1  # prepare seqlun for next transmit
            self.seqlun &= 0x3f  # when overflowing, wrap around
        await WAITING_SESSIONS.acquire()
        try:
            Session.waiting_sessions.pop(self, None)
        finally:
            WAITING_SESSIONS.release()
        # render retry mechanism utterly incapable of
        # doing anything, though it shouldn't matter
        self.lastpayload = None
        self.last_payload_type = None
        response = {'netfn': payload[1] >> 2}
        # ^^ remove header of rsaddr/netfn/lun/checksum/rq/seq/lun
        del payload[0:5]
        # remove the trailing checksum
        del payload[-1]
        response['command'] = payload[0]
        if self.servermode:
            del payload[0:1]
            response['data'] = payload
        else:
            response['code'] = payload[1]
            del payload[0:2]
            response['data'] = payload
        self.timeout = initialtimeout + (0.5 * random.random())
        if not self.servermode and len(self.pendingpayloads) > 0:
            (nextpayload, nextpayloadtype, retry) = \
                self.pendingpayloads.popleft()
            await self.send_payload(payload=nextpayload,
                              payload_type=nextpayloadtype,
                              retry=retry)
        if self.ipmicallback:
            rsp = self.ipmicallback(response)
            if rsp:
                await rsp


    async def _timedout(self):
        if not self.lastpayload:
            return
        self.nowait = True
        self.timeout += 1
        if self.timeout > self.maxtimeout:
            if not self.logontries:
                response = {'error': 'timeout', 'code': 0xffff}
                if self.ipmicallback:
                    await self.ipmicallback(response)
                self.nowait = False
                await self._mark_broken()
                return
            else:
                self.maxtimeout = 2
                if self.sessioncontext == 'ESTABLISHED':
                    self.onlogpayload = self.lastpayload
                    self.onlogpayloadtype = self.last_payload_type
                    self.maxtimeout = 6
                await self._relog()
                return
        elif self.sessioncontext == 'FAILED':
            self.lastpayload = None
            self.onlogpayload = None
            self.nowait = False
            return
        if self.sessioncontext == 'OPENSESSION':
            # In this case, we want to craft a new session request to have
            # unambiguous session id regardless of how packet was dropped or
            # delayed in this case, it's safe to just redo the request
            self.lastpayload = None
            await self._open_rmcpplus_request()
        elif (self.sessioncontext == 'EXPECTINGRAKP2'
              or self.sessioncontext == 'EXPECTINGRAKP4'):
            # If we can't be sure which RAKP was dropped or if RAKP3/4 was just
            # delayed, the most reliable thing to do is rewind and start over
            # bmcs do not take kindly to receiving RAKP1 or RAKP3 twice
            await self._relog()
        else:  # in IPMI case, the only recourse is to act as if the packet is
            # idempotent.  SOL has more sophisticated retry handling
            # the biggest risks are reset sp which is often fruitless to retry
            # and chassis reset, which sometimes will shoot itself
            # systematically in the head in a shared port case making replies
            # impossible
            self.hasretried = 1  # remember so that we can track taboo
            # combinations
            # of sequence number, netfn, and lun due to
            # ambiguity on the wire
            await self.send_payload()
        self.nowait = False

    async def _xmit_packet(self, retry=True, timeout=None):
        if self.sequencenumber:  # seq number of zero will be left alone, it is
            # special, otherwise increment
            self.sequencenumber += 1
        if self.sockaddr:
            _io_sendto(self.socket, self.netpacket, self.sockaddr)
        else:
            # he have not yet picked a working sockaddr for this connection,
            # try all the candidates that getaddrinfo provides
            self.allsockaddrs = []
            myport = self.socket.getsockname()[1]
            try:
                for res in socket.getaddrinfo(self.bmc,
                                              self.port,
                                              0,
                                              socket.SOCK_DGRAM):
                    sockaddr = res[4]
                    if ipv6support and res[0] == socket.AF_INET:
                        # convert the sockaddr to AF_INET6
                        newhost = '::ffff:' + sockaddr[0]
                        sockaddr = (newhost, sockaddr[1], 0, 0)
                    self.allsockaddrs.append(sockaddr)
                    if sockaddr not in Session.bmc_handlers:
                        Session.bmc_handlers[sockaddr] = {}
                    Session.bmc_handlers[sockaddr][myport] = self
                    _io_sendto(self.socket, self.netpacket, sockaddr)
                try:
                    del Session.initting_sessions[(self.bmc, self.userid,
                                                   self.password, self.port,
                                                   self.kgo)]
                except KeyError:
                    pass
            except socket.gaierror:
                raise exc.IpmiException(
                    "Unable to transmit to specified address")
        if retry:
            await WAITING_SESSIONS.acquire()
            try:
                Session.waiting_sessions[self] = {}
                Session.waiting_sessions[self]['ipmisession'] = self
                if timeout is not None:
                    self.expiration = timeout + _monotonic_time()
                else:
                    self.expiration = self.timeout + _monotonic_time()
                Session.waiting_sessions[self]['timeout'] = self.expiration
            finally:
                WAITING_SESSIONS.release()

    async def logout(self, sessionok=True):

        if self.cleaningup:
            self.nowait = True
        if self.logged:
            if self.sol_handler:
                await self.raw_command(
                    netfn=6, command=0x49, data=(1, 1, 0, 0, 0, 0),
                    retry=sessionok)
            await self.raw_command(
                command=0x3c, netfn=6,
                data=struct.unpack(
                    "4B", struct.pack("I", self.sessionid)),
                retry=False)
        # stop trying for a keepalive,
        self.lastpayload = None
        await KEEPALIVE_SESSIONS.acquire()
        try:
            Session.keepalive_sessions.pop(self, None)
        finally:
            KEEPALIVE_SESSIONS.release()
        self.logged = 0
        self.onlogpayload = None
        self.logging = False
        if self._customkeepalives:
            for ka in list(self._customkeepalives):
                # Be thorough and notify parties through their custom
                # keepalives.  In practice, this *should* be the same, but
                # if a code somehow makes duplicate SOL handlers,
                # this would notify all the handlers rather than just the
                # last one to take ownership
                if self._customkeepalives[ka][1] is None:
                    continue
                await self._customkeepalives[ka][1](
                    {'error': 'Session Disconnected'})
        self._customkeepalives = None
        if not self.broken:
            self.socketpool[self.socket] -= 1
            self.broken = True
            # since this session is broken, remove it from the handler list
            # This allows constructor to create a new, functional object to
            # replace this one
            myport = self.socket.getsockname()[1]
            for sockaddr in self.allsockaddrs:
                if (sockaddr in Session.bmc_handlers
                        and myport in Session.bmc_handlers[sockaddr]):
                    del Session.bmc_handlers[sockaddr][myport]
                    if Session.bmc_handlers[sockaddr] == {}:
                        del Session.bmc_handlers[sockaddr]
        self.nowait = False
        self.socketpool[self.socket] -= 1
        return {'success': True}


if __name__ == "__main__":
    import sys

    ipmis = Session(bmc=sys.argv[1],
                    userid=sys.argv[2],
                    password=os.environ['IPMIPASS'])
    print(ipmis.raw_command(command=2, data=[1], netfn=0))
    print(get_ipmi_error({'command': 8, 'code': 128, 'netfn': 1}))
