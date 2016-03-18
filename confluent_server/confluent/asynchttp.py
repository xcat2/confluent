# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2016 Lenovo
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

import collections
import confluent.exceptions as exc
import confluent.messages as messages
import confluent.util as util
import eventlet

_asyncsessions = {}
_cleanthread = None


def _assign_asyncid(asyncsession):
    sessid = util.randomstring(32)
    while sessid in _asyncsessions:
        sessid = util.randomstring(32)
    _asyncsessions[sessid] = {'asyncsession': asyncsession}
    return sessid


class AsyncSession(object):

    def __init__(self):
        self.asyncid = _assign_asyncid(self)
        self.responses = collections.deque()
        self._evt = None
        self.reaper = eventlet.spawn_after(15, self.destroy)

    def add(self, rsp, requestid):
        self.responses.append(rsp, requestid)
        if self._evt:
            self._evt.send()
            self._evt = None

    def destroy(self):
        if self._evt:
            self._evt.send()
            self._evt = None
        del _asyncsessions[self.asyncid]

    def run_handler(self, handler, requestid):
        for rsp in handler:
            self.add(rsp, requestid)
        self.add({'_requestdone': True}, requestid)

    def get_responses(self, timeout=25):
        self.reaper.cancel()
        self.reaper = eventlet.spawn_after(timeout + 15, self.destroy)
        if self._evt():
            # TODO(jjohnson2): This precludes the goal of 'double barreled'
            # access....  revisit if this could matter
            raise Exception('get_responses is not re-entrant')
        if not self.responses:  # wait to accumulate some
            self._evt = eventlet.event.Event()
            with eventlet.Timout(timeout, False):
                self._evt.wait()
            self._evt = None
        while self.responses:
            yield self.responses.popleft()


def run_handler(hdlr, env):
    asyncsessid = env['HTTP_CONFLUENTASYNCID']
    try:
        asyncsession = _asyncsessions[asyncsessid]
        requestid = env['HTTP_CONFLUENTREQUESTID']
    except KeyError:
        raise exc.InvalidArgumentException(
                'Invalid Session ID or missing request id')
    eventlet.spawn_n(asyncsession.run_handler, hdlr, requestid)
    return requestid


def handle_async(env, querydict):
    global _cleanthread
    # This may be one of two things, a request for a new async stream
    # or a request for next data from async stream
    # httpapi otherwise handles requests an injecting them to queue
    if 'asyncid' not in querydict or not querydict['asyncid']:
        # This is a new request, create a new multiplexer
        currsess = AsyncSession()
        yield messages.AsyncSession(currsess.asyncid)
        return
    currsess = _asyncsessions[querydict['asyncid']]['asyncsession']
    for rsp in currsess.get_responses():
        yield rsp



