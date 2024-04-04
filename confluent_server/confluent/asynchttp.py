# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2016-2018 Lenovo
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

# Overall, the result of this shall be:
# - Web clients can create the same out-of-order responsiveness as socket
#   clients (but with more complexity on their end)
# - Web clients can share single request among console sessions
# - Web clients can get async notify of things like node add/remove, events

# This provides an async strategy to http clients.  The design is that a http
# session may have an 'async' resource.  In such a case, any requests are
# queued and immediately the response is given accepting the queued request.
# A request flags itself as queue-compatible through an HTTP header indicating
# the identifier of the async thread.  As responses happen to the queued
# request, data is dispatched to the first registered poller for data on
# the session.  This way, a client may elect to provide multiple pollers
# to mitigate general choppiness of http network pattern.  It may not be
# worth it, but it's possible.

# Additionally support console session multiplexing, to mitigate needed
# connection count.

# Also, this should allow a client to register for notifications of things
# like node add/delete or an event firing, ultimately.

# Much like console sessions, these will be reaped if a client spends too
# far away.

import asyncio
import collections
import confluent.exceptions as exc
import confluent.messages as messages
import confluent.util as util
import eventlet
import greenlet
import time

_asyncsessions = {}
_cleanthread = None
_consolesessions = None


def _assign_asyncid(asyncsession):
    sessid = util.randomstring(32)
    while sessid in _asyncsessions:
        sessid = util.randomstring(32)
    _asyncsessions[sessid] = {'asyncsession': asyncsession}
    return sessid


class AsyncTermRelation(object):
    # Need to keep an association of term object to async
    # This allows the async handler to know the context of
    # outgoing data to provide to calling code
    def __init__(self, termid, asynchdl):
        self.asynchdl = asynchdl
        self.termid = termid

    def got_data(self, data):
        self.asynchdl.add(self.termid, data)


class AsyncSession(object):

    def __init__(self, wshandler=None):
        self.asyncid = _assign_asyncid(self)
        self.responses = collections.deque()
        self.wshandler = wshandler
        self._evt = None
        self.termrelations = []
        self.consoles = set([])
        if not wshandler:
            self.reaper = eventlet.spawn_after(15, self.destroy)

    async def add(self, requestid, rsp):
        if self.wshandler:
            await self.wshandler(messages.AsyncMessage((requestid, rsp)))
        if self.responses is None:
            return
        self.responses.append((requestid, rsp))
        if self._evt:


            self._evt.send()
            self._evt = None

    def set_term_relation(self, env):
        # need a term relation to keep track of what data belongs
        # to what object (since the callback does not provide context
        # for data, and here ultimately the client is responsible
        # for sorting out which is which.
        termrel = AsyncTermRelation(env['HTTP_CONFLUENTREQUESTID'], self)
        self.termrelations.append(termrel)
        return termrel

    def add_console_session(self, sessionid):
        self.consoles.add(sessionid)

    def destroy(self):
        if self._evt:
            self._evt.send()
            self._evt = None
        for console in self.consoles:
            _consolesessions[console]['session'].destroy()
        self.consoles = set([])
        self.responses = None
        del _asyncsessions[self.asyncid]

    async def run_handler(self, handler, requestid):
        try:
            handler = await handler
            async for rsp in handler:
                await self.add(requestid, rsp)
            await self.add(requestid, messages.AsyncCompletion())
        except Exception as e:
            print(repr(e))
            await self.add(requestid, e)

    def get_responses(self, timeout=25):
        self.reaper.cancel()
        self.reaper = eventlet.spawn_after(timeout + 15, self.destroy)
        nextexpiry = time.time() + 90
        for csess in list(self.consoles):
            try:
                _consolesessions[csess]['expiry'] = nextexpiry
            except KeyError:  # session has been closed elsewhere
                self.consoles.discard(csess)
        if self._evt:
            # TODO(jjohnson2): This precludes the goal of 'double barreled'
            # access....  revisit if this could matter
            raise Exception('get_responses is not re-entrant')
        if not self.responses:  # wait to accumulate some
            self._evt = eventlet.event.Event()
            with eventlet.Timeout(timeout, False):
                self._evt.wait()
            self._evt = None
        while self.responses:
            yield self.responses.popleft()


async def run_handler(hdlr, req):
    asyncsessid = req.headers['ConfluentAsyncId']
    try:
        asyncsession = _asyncsessions[asyncsessid]['asyncsession']
        requestid = req.headers['ConfluentRequestId']
    except KeyError:
        raise exc.InvalidArgumentException(
                'Invalid Session ID or missing request id')
    cloop = asyncio.get_event_loop()
    cloop.create_task(asyncsession.run_handler(hdlr, requestid))
    #eventlet.spawn_n(asyncsession.run_handler, hdlr, requestid)
    return requestid


def get_async(env, querydict):
    global _cleanthread
    return _asyncsessions[env['HTTP_CONFLUENTASYNCID']]['asyncsession']


def handle_async(env, querydict, threadset, wshandler=None):
    global _cleanthread
    # This may be one of two things, a request for a new async stream
    # or a request for next data from async stream
    # httpapi otherwise handles requests an injecting them to queue
    if 'asyncid' not in querydict or not querydict['asyncid']:
        # This is a new request, create a new multiplexer
        currsess = AsyncSession(wshandler)
        if wshandler:
            yield currsess
            return
        yield messages.AsyncSession(currsess.asyncid)
        return
    if  querydict['asyncid'] not in _asyncsessions:
        raise exc.InvalidArgumentException(
                'Invalid or expired async id')
    mythreadid = greenlet.getcurrent()
    threadset.add(mythreadid)
    loggedout = None
    currsess = None
    try:
        currsess = _asyncsessions[querydict['asyncid']]['asyncsession']
        for rsp in currsess.get_responses():
            yield messages.AsyncMessage(rsp)
    except greenlet.GreenletExit as ge:
        loggedout = ge
    threadset.discard(mythreadid)
    if loggedout is not None:
        currsess.destroy()
        raise exc.LoggedOut()


def set_console_sessions(consolesessions):
    global _consolesessions
    _consolesessions = consolesessions
