# Copyright 2014 IBM Corporation
# Copyright 2015-2019 Lenovo
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
#
"""This represents the low layer message framing portion of IPMI"""

import struct
import threading

import aiohmi.exceptions as exc
from aiohmi.ipmi.private import constants
from aiohmi.ipmi.private import session
from aiohmi.ipmi.private.util import _monotonic_time


class Console(object):
    """IPMI SOL class.

    This object represents an SOL channel, multiplexing SOL data with
    commands issued by ipmi.command.

    :param bmc: hostname or ip address of BMC
    :param userid: username to use to connect
    :param password: password to connect to the BMC
    :param iohandler: Either a function to call with bytes, a filehandle to
                      use for input and output, or a tuple of (input, output)
                      handles
    :param force: Set to True to force on or False to force off
    :param kg: optional parameter for BMCs configured to require it
    """

    # TODO(jbjohnso): still need an exit and a data callin function
    def __init__(self, bmc, userid, password,
                 iohandler, port=623,
                 force=False, kg=None):
        self.outputlock = threading.RLock()
        self.keepaliveid = None
        self.connected = False
        self.broken = False
        self.out_handler = iohandler
        self.remseq = 0
        self.myseq = 0
        self.lastsize = 0
        self.retriedpayload = 0
        self.pendingoutput = []
        self.awaitingack = False
        self.activated = False
        self.force_session = force
        self.port = port
        self.ipmi_session = None
        self.callgotsession = None
        self.bmc = bmc
        self.userid = userid
        self.password = password
        self.port = port
        self.kg = kg
        self.broken = False

    async def connect(self):
        bmc = self.bmc
        userid = self.userid
        password = self.password
        port = self.port
        kg = self.kg
        self.ipmi_session = await session.Session(
            bmc=bmc, userid=userid, password=password, port=port, kg=kg)
        # induce one iteration of the loop, now that we would be
        # prepared for it in theory
        await self._got_session({})


    async def _got_session(self, response):
        """Private function to navigate SOL payload activation"""
        if 'error' in response:
            await self._print_error(response['error'])
            return
        if not self.ipmi_session:
            self.callgotsession = response
            return
        # Send activate sol payload directive
        # netfn= 6 (application)
        # command = 0x48 (activate payload)
        # data = (1, sol payload type
        #        1, first instance
        #        0b11000000, -encrypt, authenticate,
        #                      disable serial/modem alerts, CTS fine
        #        0, 0, 0 reserved
        response = await self.ipmi_session.raw_command(netfn=0x6, command=0x48,
                                                       data=(1, 1, 192, 0, 0, 0))
        # given that these are specific to the command,
        # it's probably best if one can grep the error
        # here instead of in constants
        sol_activate_codes = {
            0x81: 'SOL is disabled',
            0x82: 'Maximum SOL session count reached',
            0x83: 'Cannot activate payload with encryption',
            0x84: 'Cannot activate payload without encryption',
        }
        if 'code' in response and response['code']:
            if response['code'] in constants.ipmi_completion_codes:
                await self._print_error(
                    constants.ipmi_completion_codes[response['code']])
                return
            elif response['code'] == 0x80:
                if self.force_session and not self.retriedpayload:
                    self.retriedpayload = 1
                    sessrsp = await self.ipmi_session.raw_command(
                        netfn=0x6,
                        command=0x49,
                        data=(1, 1, 0, 0, 0, 0))
                    await self._got_session(sessrsp)
                    return
                else:
                    await self._print_error('SOL Session active for another client')
                    return
            elif response['code'] in sol_activate_codes:
                await self._print_error(sol_activate_codes[response['code']])
                return
            else:
                await self._print_error(
                    'SOL encountered Unrecognized error code %d' %
                    response['code'])
                return
        if 'error' in response:
            await self._print_error(response['error'])
            return
        self.activated = True
        # data[0:3] is reserved except for the test mode, which we don't use
        data = response['data']
        self.maxoutcount = (data[5] << 8) + data[4]
        # BMC tells us this is the maximum allowed size
        # data[6:7] is the promise of how small packets are going to be, but we
        # don't have any reason to worry about it
        # some BMCs disagree on the endianness, so do both
        valid_ports = (self.port, struct.unpack(
            '<H', struct.pack('>H', self.port))[0])
        if (data[8] + (data[9] << 8)) not in valid_ports:
            # TODO(jbjohnso): support atypical SOL port number
            raise NotImplementedError("Non-standard SOL Port Number")
        # ignore data[10:11] for now, the vlan detail, shouldn't matter to this
        # code anyway...
        # NOTE(jbjohnso):
        # We will use a special purpose keepalive
        if self.ipmi_session.sol_handler is not None:
            # If there is erroneously another SOL handler already, notify
            # it of newly established session
            await self.ipmi_session.sol_handler({'error': 'Session Disconnected'})
        self.keepaliveid = self.ipmi_session.register_keepalive(
            cmd={'netfn': 6, 'command': 0x4b, 'data': (1, 1)},
            callback=self._got_payload_instance_info)
        self.ipmi_session.sol_handler = self._got_sol_payload
        self.connected = True
        # self._sendpendingoutput() checks len(self._sendpendingoutput)
        await self._sendpendingoutput()

    async def _got_payload_instance_info(self, response):
        if 'error' in response:
            self.activated = False
            await self._print_error(response['error'])
            return
        currowner = struct.unpack(
            "<I", struct.pack('4B', *response['data'][:4]))
        if currowner[0] != self.ipmi_session.sessionid:
            # the session is deactivated or active for something else
            self.activated = False
            await self._print_error('SOL deactivated')
            return
        # ok, still here, that means session is alive, but another
        # common issue is firmware messing with mux on reboot
        # this would be a nice thing to check, but the serial channel
        # number is needed and there isn't an obvious means to reliably
        # discern which channel or even *if* the serial port in question
        # correlates at all to an ipmi channel to check mux

    def _addpendingdata(self, data):
        with self.outputlock:
            if isinstance(data, dict):
                self.pendingoutput.append(data)
            else:  # it is a text situation
                if (len(self.pendingoutput) == 0
                        or isinstance(self.pendingoutput[-1], dict)):
                    self.pendingoutput.append(data)
                else:
                    self.pendingoutput[-1] += data

    def _got_cons_input(self, handle):
        """Callback for handle events detected by ipmi session"""

        self._addpendingdata(handle.read())
        if not self.awaitingack:
            self._sendpendingoutput()

    async def close(self):
        """Shut down an SOL session"""

        if self.ipmi_session:
            self.ipmi_session.unregister_keepalive(self.keepaliveid)
        if self.activated and self.ipmi_session is not None:
            try:
                await self.ipmi_session.raw_command(netfn=6, command=0x49,
                                              data=(1, 1, 0, 0, 0, 0))
            except exc.IpmiException:
                # if underlying ipmi session is not working, then
                # run with the implicit success
                pass

    async def send_data(self, data):
        if self.broken:
            return
        self._addpendingdata(data)
        if not self.connected:
            return
        if not self.awaitingack:
            await self._sendpendingoutput()

    async def send_break(self):
        self._addpendingdata({'break': 1})
        if not self.connected:
            return
        if not self.awaitingack:
            await self._sendpendingoutput()

    @classmethod
    def wait_for_rsp(cls, timeout):
        """Delay for no longer than timeout for next response.

        This acts like a sleep that exits on activity.

        :param timeout: Maximum number of seconds before returning
        """
        return session.Session.wait_for_rsp(timeout=timeout)

    async def _sendpendingoutput(self):
        with self.outputlock:
            dobreak = False
            chunk = ''
            if len(self.pendingoutput) == 0:
                return
            if isinstance(self.pendingoutput[0], dict):
                if 'break' in self.pendingoutput[0]:
                    dobreak = True
                else:
                    del self.pendingoutput[0]
                    raise ValueError
                del self.pendingoutput[0]
            elif len(self.pendingoutput[0]) > self.maxoutcount:
                chunk = self.pendingoutput[0][:self.maxoutcount]
                self.pendingoutput[0] = self.pendingoutput[0][
                    self.maxoutcount:]
            else:
                chunk = self.pendingoutput[0]
                del self.pendingoutput[0]
            await self._sendoutput(chunk, sendbreak=dobreak)

    async def _sendoutput(self, output, sendbreak=False):
        self.myseq += 1
        self.myseq &= 0xf
        if self.myseq == 0:
            self.myseq = 1
        # currently we don't try to combine ack with outgoing data
        # so we use 0 for ack sequence number and accepted character
        # count
        breakbyte = 0
        if sendbreak:
            breakbyte = 0b10000
        try:
            payload = bytearray((self.myseq, 0, 0, breakbyte)) + output
        except TypeError:  # bytearray hits unicode...
            payload = bytearray((self.myseq, 0, 0, breakbyte
                                 )) + output.encode('utf8')
        self.lasttextsize = len(output)
        needskeepalive = False
        if self.lasttextsize == 0:
            needskeepalive = True
        self.awaitingack = True
        self.lastpayload = payload
        await self.send_payload(payload, retry=False, needskeepalive=needskeepalive)
        retries = 5
        while retries and self.awaitingack:
            expiry = _monotonic_time() + 5.5 - retries
            while self.awaitingack and _monotonic_time() < expiry:
                await self.wait_for_rsp(0.5)
            if self.awaitingack:
                await self.send_payload(payload, retry=False,
                                        needskeepalive=needskeepalive)
            retries -= 1
        if not retries:
            await self._print_error('Connection lost')

    async def send_payload(self, payload, payload_type=1, retry=True,
                     needskeepalive=False):
        while not (self.connected or self.broken):
            session.Session.wait_for_rsp(timeout=10)
        if self.ipmi_session is None or not self.ipmi_session.logged:
            await self._print_error('Session no longer connected')
            raise exc.IpmiException('Session no longer connected')
        await self.ipmi_session.send_payload(payload,
                                       payload_type=payload_type,
                                       retry=retry,
                                       needskeepalive=needskeepalive)

    async def _print_info(self, info):
        await self._print_data({'info': info})

    async def _print_error(self, error):
        self.broken = True
        if self.ipmi_session:
            self.ipmi_session.unregister_keepalive(self.keepaliveid)
            if (self.ipmi_session.sol_handler
                    and self.ipmi_session.sol_handler.__self__ is self):
                self.ipmi_session.sol_handler = None
            self.ipmi_session = None
        if type(error) == dict:
            await self._print_data(error)
        else:
            await self._print_data({'error': error})

    async def _print_data(self, data):
        """Convey received data back to caller in the format of their choice.

        Caller may elect to provide this class filehandle(s) or else give a
        callback function that this class will use to convey data back to
        caller.
        """
        await self.out_handler(data)

    async def _got_sol_payload(self, payload):
        """SOL payload callback"""

        # TODO(jbjohnso) test cases to throw some likely scenarios at functions
        # for example, retry with new data, retry with no new data
        # retry with unexpected sequence number
        if type(payload) == dict:  # we received an error condition
            self.activated = False
            await self._print_error(payload)
            return
        newseq = payload[0] & 0b1111
        ackseq = payload[1] & 0b1111
        ackcount = payload[2]
        nacked = payload[3] & 0b1000000
        poweredoff = payload[3] & 0b100000
        deactivated = payload[3] & 0b10000
        breakdetected = payload[3] & 0b100
        # for now, ignore overrun.  I assume partial NACK for this reason or
        # for no reason would be treated the same, new payload with partial
        # data.
        remdata = ""
        remdatalen = 0
        if newseq != 0:  # this packet at least has some data to send to us..
            if len(payload) > 4:
                remdatalen = len(payload[4:])  # store remote len before dupe
                # retry logic, we must ack *this* many even if it is
                # a retry packet with new partial data
                remdata = bytes(payload[4:])
            if newseq == self.remseq:  # it is a retry, but could have new data
                if remdatalen > self.lastsize:
                    remdata = bytes(remdata[4 + self.lastsize:])
                else:  # no new data...
                    remdata = ""
            else:  # TODO(jbjohnso) what if remote sequence number is wrong??
                self.remseq = newseq
            self.lastsize = remdatalen
            if remdata:  # Do not subject callers to empty data
                await self._print_data(remdata)
            ackpayload = bytearray((0, self.remseq, remdatalen, 0))
            # Why not put pending data into the ack? because it's rare
            # and might be hard to decide what to do in the context of
            # retry situation
            try:
                await self.send_payload(ackpayload, retry=False)
            except exc.IpmiException:
                # if the session is broken, then close the SOL session
                await self.close()
        if self.myseq != 0 and ackseq == self.myseq:  # the bmc has something
            # to say about last xmit
            self.awaitingack = False
            if nacked and not breakdetected:  # the BMC was in some way unhappy
                if poweredoff:
                    await self._print_info("Remote system is powered down")
                if deactivated:
                    self.activated = False
                    await self._print_error("Remote IPMI console disconnected")
                else:  # retry all or part of packet, but in a new form
                    # also add pending output for efficiency and ease
                    newtext = self.lastpayload[4 + ackcount:]
                    with self.outputlock:
                        if (self.pendingoutput
                                and not isinstance(self.pendingoutput[0],
                                                   dict)):
                            self.pendingoutput[0] = \
                                newtext + self.pendingoutput[0]
                        else:
                            self.pendingoutput = [newtext] + self.pendingoutput
            # self._sendpendingoutput() checks len(self._sendpendingoutput)
            await self._sendpendingoutput()
        elif ackseq != 0 and self.awaitingack:
            # if an ack packet came in, but did not match what we
            # expected, retry our payload now.
            # the situation that was triggered was a senseless retry
            # when data came in while we xmitted.  In theory, a BMC
            # should handle a retry correctly, but some do not, so
            # try to mitigate by avoiding overeager retries
            # occasional retry of a packet
            # sooner than timeout suggests is evidently a big deal
            await self.send_payload(payload=self.lastpayload, retry=False)

    def main_loop(self):
        """Process all events until no more sessions exist.

        If a caller is a simple little utility, provide a function to
        eternally run the event loop.  More complicated usage would be expected
        to provide their own event loop behavior, though this could be used
        within the async implementation of caller's choice if desired.
        """
        # wait_for_rsp promises to return a false value when no sessions are
        # alive anymore
        # TODO(jbjohnso): wait_for_rsp is not returning a true value for our
        # own session
        while (1):
            session.Session.wait_for_rsp(timeout=600)


class ServerConsole(Console):
    """IPMI SOL class.

    This object represents an SOL channel, multiplexing SOL data with
    commands issued by ipmi.command.

    :param session: IPMI session
    :param iohandler: I/O handler
    """

    def __init__(self, _session, iohandler, force=False):
        self.outputlock = threading.RLock()
        self.keepaliveid = None
        self.connected = True
        self.broken = False
        self.out_handler = iohandler
        self.remseq = 0
        self.myseq = 0
        self.lastsize = 0
        self.retriedpayload = 0
        self.pendingoutput = []
        self.awaitingack = False
        self.activated = True
        self.force_session = force
        self.ipmi_session = _session
        self.ipmi_session.sol_handler = self._got_sol_payload
        self.maxoutcount = 256
        self.poweredon = True

        session.Session.wait_for_rsp(0)

    async def _got_sol_payload(self, payload):
        """SOL payload callback"""

        # TODO(jbjohnso) test cases to throw some likely scenarios at functions
        # for example, retry with new data, retry with no new data
        # retry with unexpected sequence number
        if type(payload) == dict:  # we received an error condition
            self.activated = False
            await self._print_error(payload)
            return
        newseq = payload[0] & 0b1111
        ackseq = payload[1] & 0b1111
        ackcount = payload[2]
        nacked = payload[3] & 0b1000000
        breakdetected = payload[3] & 0b10000
        # for now, ignore overrun.  I assume partial NACK for this reason or
        # for no reason would be treated the same, new payload with partial
        # data.
        remdata = ""
        remdatalen = 0
        flag = 0
        if not self.poweredon:
            flag |= 0b1100000
        if not self.activated:
            flag |= 0b1010000
        if newseq != 0:  # this packet at least has some data to send to us..
            if len(payload) > 4:
                remdatalen = len(payload[4:])  # store remote len before dupe
                # retry logic, we must ack *this* many even if it is
                # a retry packet with new partial data
                remdata = bytes(payload[4:])
            if newseq == self.remseq:  # it is a retry, but could have new data
                if remdatalen > self.lastsize:
                    remdata = bytes(remdata[4 + self.lastsize:])
                else:  # no new data...
                    remdata = ""
            else:  # TODO(jbjohnso) what if remote sequence number is wrong??
                self.remseq = newseq
            self.lastsize = remdatalen
            ackpayload = bytearray((0, self.remseq, remdatalen, flag))
            # Why not put pending data into the ack? because it's rare
            # and might be hard to decide what to do in the context of
            # retry situation
            try:
                self.send_payload(ackpayload, retry=False)
            except exc.IpmiException:
                # if the session is broken, then close the SOL session
                self.close()
            if remdata:  # Do not subject callers to empty data
                await self._print_data(remdata)
        if self.myseq != 0 and ackseq == self.myseq:  # the bmc has something
            # to say about last xmit
            self.awaitingack = False
            if nacked and not breakdetected:  # the BMC was in some way unhappy
                newtext = self.lastpayload[4 + ackcount:]
                with self.outputlock:
                    if (self.pendingoutput
                            and not isinstance(self.pendingoutput[0], dict)):
                        self.pendingoutput[0] = newtext + self.pendingoutput[0]
                    else:
                        self.pendingoutput = [newtext] + self.pendingoutput
            # self._sendpendingoutput() checks len(self._sendpendingoutput)
            self._sendpendingoutput()
        elif ackseq != 0 and self.awaitingack:
            # if an ack packet came in, but did not match what we
            # expected, retry our payload now.
            # the situation that was triggered was a senseless retry
            # when data came in while we xmitted.  In theory, a BMC
            # should handle a retry correctly, but some do not, so
            # try to mitigate by avoiding overeager retries
            # occasional retry of a packet
            # sooner than timeout suggests is evidently a big deal
            self.send_payload(payload=self.lastpayload)

    def send_payload(self, payload, payload_type=1, retry=True,
                     needskeepalive=False):
        while not (self.connected or self.broken):
            session.Session.wait_for_rsp(timeout=10)
        self.ipmi_session.send_payload(payload,
                                       payload_type=payload_type,
                                       retry=retry,
                                       needskeepalive=needskeepalive)

    def close(self):
        """Shut down an SOL session"""

        self.activated = False
