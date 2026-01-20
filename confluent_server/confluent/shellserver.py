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

# This module tracks each node, tenants currently active shell sessions
# 'ConsoleSession' objects from consoleserver are used, but with the additional
# capacity for having a multiple of sessions per node active at a given time


import confluent.consoleserver as consoleserver
import confluent.exceptions as exc
import confluent.messages as msg
import confluent.tasks as tasks
import time
activesessions = {}

_reaper = None

def reapsessions():
    while True:
        eventlet.sleep(30)
        for clientid in activesessions:
            currcli = activesessions[clientid]
            for sesshdl in list(currcli):
                currsess = currcli[sesshdl]
                if currsess.numusers == 0 and currsess.expiry < time.time():
                    currsess.close()
                    del activesessions[clientid][sesshdl]

class _ShellHandler(consoleserver.ConsoleHandler):
    _plugin_path = '/nodes/{0}/_shell/session'
    _genwatchattribs = False
    _logtobuffer = False

    def __init__(self, node, configmanager, width=80, height=24, prefix=''):
        super().__init__(node, configmanager, width, height)
        self.termprefix = prefix
        self.numusers = 0
        global _reaper
        if _reaper is None:
            _reaper = eventlet.spawn(reapsessions)


    def check_collective(self, attrvalue):
        return

    def log(self, *args, **kwargs):
        # suppress logging through proving a stub 'log' function
        return

    #def feedbuffer(self, data):
    #    return
    #    #return super().feedbuffer(data)

    #async #def get_recent(self):
    #    #retdata, connstate = await super(_ShellHandler, self).get_recent()
    #    return '', {} # connstate

    def _got_disconnected(self):
        self.connectstate = 'closed'
        tasks.spawn(self._bgdisconnect())

    async def _bgdisconnect(self):
        await self._send_rcpts({'connectstate': self.connectstate})
        for session in list(self.livesessions):
            await session.destroy()
        self.feedbuffer('\x1bc')




def get_sessions(tenant, node, user):
    """Get sessionids active for node

    Given a tenant, nodename, and user; provide an iterable of sessionids.
    Each permutation of tenant, nodename and user have a distinct set of shell
    sessions.

    :param tenant:  The tenant identifier for the current scope
    :param node:  The nodename of the current scope.
    :param user: The confluent user that will 'own' the session.
    """
    return activesessions.get((tenant, node, user), {})


def get_session(tenant, node, user, sessionid):
    return activesessions.get((tenant, node, user), {}).get(sessionid, None)





class ShellSession(consoleserver.ConsoleSession):
    """Create a new socket to converse with a node shell session

    This object provides a filehandle that can be read/written
    too in a normal fashion and the concurrency, logging, and
    event watching will all be handled seamlessly.  It represents a remote
    CLI shell session.

    :param node: Name of the node for which this session will be created
    :param configmanager: A configuration manager object for current context
    :param username: Username for which this session object will operate
    :param datacallback: An asynchronous data handler, to be called when data
                         is available.
    :param skipreplay: If true, will skip the attempt to redraw the screen
    :param sessionid: An optional identifier to match a running session or
                      customize the name of a new session.
    """

    def __init__(self, node, configmanager, username, datacallback=None,
                 skipreplay=False, sessionid=None, width=80, height=24):
        self.sessionid = sessionid
        self.configmanager = configmanager
        self.node = node
        super(ShellSession, self).__init__(node, configmanager, username,
                                           datacallback, skipreplay,
                                           width=width, height=height)

    def connect_session(self):
        global activesessions
        tenant = self.configmanager.tenant
        if (self.configmanager.tenant, self.node, self.username) not in activesessions:
            activesessions[(tenant, self.node, self.username)] = {}
        if self.sessionid is None:
            self.sessionid = 1
            while str(self.sessionid) in activesessions[(tenant, self.node, self.username)]:
                self.sessionid += 1
            self.sessionid = str(self.sessionid)
        conshdl = activesessions[(tenant, self.node, self.username)].get(self.sessionid, None)
        if conshdl and conshdl.connectstate == 'closed':
            del activesessions[(tenant, self.node, self.username)][self.sessionid]
            conshdl = None
        if not conshdl:
            activesessions[(tenant, self.node, self.username)][self.sessionid] = _ShellHandler(self.node, self.configmanager, width=self.width, height=self.height, prefix='s_{}_{}'.format(self.username, self.sessionid))
            conshdl = activesessions[(self.configmanager.tenant, self.node, self.username)][self.sessionid]
        self.conshdl = conshdl
        self.conshdl.numusers += 1

    async def destroy(self):
        try:
            self.conshdl.numusers -= 1
            if self.conshdl.numusers == 0:
                self.conshdl.expiry = time.time() + 120

        except KeyError:
            pass
        return await super(ShellSession, self).destroy()


async def create(nodes, element, configmanager, inputdata):
    # For creating a resource, it really has to be handled
    # in httpapi/sockapi specially, like a console.
    raise exc.InvalidArgumentException('Special client code required')


async def retrieve(nodes, element, configmanager, inputdata):
    tenant = configmanager.tenant
    user = configmanager.current_user
    if (tenant, nodes[0], user) in activesessions:
        for sessionid in activesessions[(tenant, nodes[0], user)]:
            yield msg.ChildCollection(sessionid)
