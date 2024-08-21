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

# This handles ownership of asynchronous behavior driving sessions
# with websockets.  There was a long-polling HTTP mechanism but that is removed
# Now it's possible to have asynchronous requests multiplexed over a single websockets
# with none of the "choppiness" inherent to multiple long-polling requests

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
import time

_asyncsessions = {}
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

    def __init__(self, wshandler):
        self.asyncid = _assign_asyncid(self)
        self.wshandler = wshandler
        self.termrelations = []
        self.consoles = set([])

    async def add(self, requestid, rsp):
        await self.wshandler(messages.AsyncMessage((requestid, rsp)))

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
        for console in self.consoles:
            _consolesessions[console]['session'].destroy()
        self.consoles = set([])
        del _asyncsessions[self.asyncid]

    async def run_handler(self, handler, requestid):
        try:
            # iterate_responses from core maybe? handler might return other stuff
            handler = await handler
            async for rsp in handler:
                await self.add(requestid, rsp)
            await self.add(requestid, messages.AsyncCompletion())
        except Exception as e:
            print(repr(e))
            await self.add(requestid, e)

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
    return requestid


def get_async(env, querydict):
    return _asyncsessions[env['HTTP_CONFLUENTASYNCID']]['asyncsession']


def handle_async(env, querydict, threadset, wshandler=None):
    # This may be one of two things, a request for a new async stream
    # or a request for next data from async stream
    # httpapi otherwise handles requests an injecting them to queue
    if 'asyncid' not in querydict or not querydict['asyncid']:
        # This is a new request, create a new multiplexer
        currsess = AsyncSession(wshandler)
        if wshandler:
            yield currsess
            return
    raise Exception("Long polling asynchttp is discontinued")


def set_console_sessions(consolesessions):
    global _consolesessions
    _consolesessions = consolesessions
