# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
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

# This is the common console support for confluent.  It takes over
# whatever filehandle is conversing with the client and starts
# relaying data.  It uses Ctrl-] like telnet for escape back to prompt

#we track nodes that are actively being logged, watched, or have attached
#there should be no more than one handler per node
import collections
import confluent.config.configmanager as configmodule
import confluent.exceptions as exc
import confluent.interface.console as conapi
import confluent.log as log
import confluent.core as plugin
import eventlet
import eventlet.event
import random
import traceback

_handled_consoles = {}

_genwatchattribs = frozenset(('console.method', 'console.logging'))

_tracelog = None


class _ConsoleHandler(object):
    def __init__(self, node, configmanager):
        self._dologging = True
        self._isondemand = False
        self.error = None
        self.rcpts = {}
        self.cfgmgr = configmanager
        self.node = node
        self.connectstate = 'unconnected'
        self.clientcount = 0
        self._isalive = True
        self.logger = log.Logger(node, console=True,
                                 tenant=configmanager.tenant)
        self.buffer = bytearray()
        (text, termstate) = self.logger.read_recent_text(8192)
        self.buffer += text
        self.appmodedetected = False
        self.shiftin = None
        self.reconnect = None
        if termstate & 1:
            self.appmodedetected = True
        if termstate & 2:
            self.shiftin = '0'
        self.users = {}
        self._attribwatcher = None
        self._console = None
        self.connectionthread = None
        self.send_break = None
        self._attribwatcher = self.cfgmgr.watch_attributes(
            (self.node,), _genwatchattribs, self._attribschanged)
        self.check_isondemand()
        if not self._isondemand:
            eventlet.spawn(self._connect)

    def check_isondemand(self):
        self._dologging = True
        attrvalue = self.cfgmgr.get_node_attributes(
            (self.node,), ('console.logging',))
        if self.node not in attrvalue:
            self._isondemand = False
        elif 'console.logging' not in attrvalue[self.node]:
            self._isondemand = False
        elif (attrvalue[self.node]['console.logging']['value'] not in (
                'full', '')):
            self._isondemand = True
        elif (attrvalue[self.node]['console.logging']['value']) == 'none':
            self._dologging = False

    def _attribschanged(self, nodeattribs, configmanager, **kwargs):
        if 'console.logging' in nodeattribs[self.node]:
            # decide whether logging changes how we react or not
            self._dologging = True
            logvalue = 'full'
            attributevalue = configmanager.get_node_attributes(
                (self.node,), ('console.logging',))
            try:
                logvalue = \
                    attributevalue[self.node]['console.logging']['value']
            except KeyError:
                pass
            if logvalue in ('full', ''):
                self._alwayson()
            else:
                self._ondemand()
                if logvalue == 'none':
                    self._dologging = False
        if not self._isondemand or self.clientcount > 0:
            eventlet.spawn(self._connect)

    def log(self, *args, **kwargs):
        if not self._dologging:
            return
        self.logger.log(*args, **kwargs)

    def _alwayson(self):
        self._isondemand = False
        if not self._console and not self.connectionthread:
            self._connect()
        else:
            self._console.ping()

    def _disconnect(self):
        if self.connectionthread:
            self.connectionthread.kill()
            self.connectionthread = None
        if self._console:
            self.log(
                logdata='console disconnected', ltype=log.DataTypes.event,
                event=log.Events.consoledisconnect)
            self._console.close()
            self._console = None
            self.connectstate = 'unconnected'
            self._send_rcpts({'connectstate': self.connectstate})

    def _ondemand(self):
        self._isondemand = True
        if self.clientcount < 1 and self._console:
            self._disconnect()

    def _connect(self):
        if self.connectionthread:
            self.connectionthread.kill()
            self.connectionthread = None
        self.connectionthread = eventlet.spawn(self._connect_backend)

    def _connect_backend(self):
        if self._console:
            self._console.close()
            self._console = None
        self.connectstate = 'connecting'
        self._send_rcpts({'connectstate': self.connectstate})
        if self.reconnect:
            self.reconnect.cancel()
            self.reconnect = None
        try:
            self._console = plugin.handle_path(
                "/nodes/%s/_console/session" % self.node,
                "create", self.cfgmgr)
        except:
            _tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                          event=log.Events.stacktrace)
        if not isinstance(self._console, conapi.Console):
            self.connectstate = 'unconnected'
            self.error = 'misconfigured'
            self._send_rcpts({'connectstate': self.connectstate,
                              'error': self.error})
            return
        self.send_break = self._console.send_break
        if self._attribwatcher:
            self.cfgmgr.remove_watcher(self._attribwatcher)
            self._attribwatcher = None
        if hasattr(self._console, "configattributes"):
            attribstowatch = self._console.configattributes | _genwatchattribs
        else:
            attribstowatch = _genwatchattribs
        self._attribwatcher = self.cfgmgr.watch_attributes(
            (self.node,), attribstowatch, self._attribschanged)
        try:
            self._console.connect(self.get_console_output)
        except exc.TargetEndpointBadCredentials:
            self.error = 'badcredentials'
            self.connectstate = 'unconnected'
            self._send_rcpts({'connectstate': self.connectstate,
                              'error': self.error})
            retrytime = 30 + (30 * random.random())
            if not self.reconnect:
                self.reconnect = eventlet.spawn_after(retrytime, self._connect)
            return
        except exc.TargetEndpointUnreachable:
            self.error = 'unreachable'
            self.connectstate = 'unconnected'
            self._send_rcpts({'connectstate': self.connectstate,
                              'error': self.error})
            retrytime = 30 + (30 * random.random())
            if not self.reconnect:
                self.reconnect = eventlet.spawn_after(retrytime, self._connect)
            return
        self._got_connected()

    def _got_connected(self):
        self.connectstate = 'connected'
        self.log(
            logdata='console connected', ltype=log.DataTypes.event,
            event=log.Events.consoleconnect)
        self._send_rcpts({'connectstate': self.connectstate})

    def _got_disconnected(self):
        self.connectstate = 'unconnected'
        self.log(
            logdata='console disconnected', ltype=log.DataTypes.event,
            event=log.Events.consoledisconnect)
        self._send_rcpts({'connectstate': self.connectstate})
        if self._isalive:
            self._connect()

    def close(self):
        self._isalive = False
        self._send_rcpts({'deleting': True})
        self._disconnect()
        if self._console:

            self._console.close()
            self._console = None
        if self.connectionthread:
            self.connectionthread.kill()
            self.connectionthread = None

    def unregister_rcpt(self, handle):
        self.clientcount -= 1
        if handle in self.rcpts:
            del self.rcpts[handle]
        self._send_rcpts({'clientcount': self.clientcount})
        if self._isondemand and self.clientcount < 1:
            self._disconnect()

    def register_rcpt(self, callback):
        self.clientcount += 1
        self._send_rcpts({'clientcount': self.clientcount})
        hdl = random.random()
        while hdl in self.rcpts:
            hdl = random.random()
        self.rcpts[hdl] = callback
        if self.connectstate == 'unconnected':
            # if console is not connected, take time to try to assert
            # connectivity now.
            if self.reconnect:
                # cancel an automated retry if one is pending
                self.reconnect.cancel()
                self.reconnect = None
            self.connectstate = 'connecting'
            eventlet.spawn(self._connect)
        return hdl

    def flushbuffer(self):
        # Logging is handled in a different stream
        # this buffer is now just for having screen redraw on
        # connect
        self.buffer = bytearray(self.buffer[-8192:])

    def get_console_output(self, data):
        # Spawn as a greenthread, return control as soon as possible
        # to the console object
        eventlet.spawn(self._handle_console_output, data)

    def attachuser(self, username):
        if username in self.users:
            self.users[username] += 1
        else:
            self.users[username] = 1
        edata = self.users[username]
        if edata > 2:  # for log purposes, only need to
            # clearly indicate redundant connections
            # not connection count
            edata = 2
        self.log(
            logdata=username, ltype=log.DataTypes.event,
            event=log.Events.clientconnect, eventdata=edata)

    def detachuser(self, username):
        self.users[username] -= 1
        if self.users[username] < 2:
            edata = self.users[username]
        else:
            edata = 2
        self.log(
            logdata=username, ltype=log.DataTypes.event,
            event=log.Events.clientdisconnect, eventdata=edata)

    def _handle_console_output(self, data):
        if type(data) == int:
            if data == conapi.ConsoleEvent.Disconnect:
                self._got_disconnected()
            return
        if '\x1b[?1l' in data:  # request for ansi mode cursor keys
            self.appmodedetected = False
        if '\x1b[?1h' in data:  # remember the session wants the client to use
            # 'application mode'  Thus far only observed on esxi
            self.appmodedetected = True
        if '\x1b)0' in data:
            # console indicates it wants access to special drawing characters
            self.shiftin = '0'
        eventdata = 0
        if self.appmodedetected:
            eventdata |= 1
        if self.shiftin is not None:
            eventdata |= 2
        self.log(data, eventdata=eventdata)
        self.buffer += data
        #TODO: analyze buffer for registered events, examples:
        #   panics
        #   certificate signing request
        if len(self.buffer) > 16384:
            self.flushbuffer()
        self._send_rcpts(data)

    def _send_rcpts(self, data):
        for rcpt in self.rcpts.itervalues():
            try:
                rcpt(data)
            except:  # No matter the reason, advance to next recipient
                pass

    def get_recent(self):
        """Retrieve 'recent' data

        Replay data in the intent to perhaps reproduce the display.
        """
        #For now, just try to seek back in buffer to find a clear screen
        #If that fails, just return buffer
        #a scheme always tracking the last clear screen would be too costly
        connstate = {
            'connectstate': self.connectstate,
            'clientcount': self.clientcount,
        }
        retdata = ''
        if self.shiftin is not None:  # detected that terminal requested a
            #shiftin character set, relay that to the terminal that cannected
            retdata += '\x1b)' + self.shiftin
        if self.appmodedetected:
            retdata += '\x1b[?1h'
        else:
            retdata += '\x1b[?1l'
        #an alternative would be to emulate a VT100 to know what the
        #whole screen would look like
        #this is one scheme to clear screen, move cursor then clear
        bufidx = self.buffer.rfind('\x1b[H\x1b[J')
        if bufidx >= 0:
            return retdata + str(self.buffer[bufidx:]), connstate
        #another scheme is the 2J scheme
        bufidx = self.buffer.rfind('\x1b[2J')
        if bufidx >= 0:
            # there was some sort of clear screen event
            # somewhere in the buffer, replay from that point
            # in hopes that it reproduces the screen
            return retdata + str(self.buffer[bufidx:]), connstate
        else:
            #we have no indication of last erase, play back last kibibyte
            #to give some sense of context anyway
            return retdata + str(self.buffer[-1024:]), connstate

    def write(self, data):
        if self.connectstate == 'connected':
            self._console.write(data)


def disconnect_node(node, configmanager):
    consk = (node, configmanager.tenant)
    if consk in _handled_consoles:
        _handled_consoles[consk].close()
        del _handled_consoles[consk]


def _nodechange(added, deleting, configmanager):
    for node in added:
        connect_node(node, configmanager)
    for node in deleting:
        disconnect_node(node, configmanager)


def _start_tenant_sessions(cfm):
    for node in cfm.list_nodes():
        try:
            connect_node(node, cfm)
        except:
            _tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                          event=log.Events.stacktrace)
    cfm.watch_nodecollection(_nodechange)


def start_console_sessions():
    global _tracelog
    _tracelog = log.Logger('trace')
    configmodule.hook_new_configmanagers(_start_tenant_sessions)


def connect_node(node, configmanager):
    consk = (node, configmanager.tenant)
    if consk not in _handled_consoles:
        _handled_consoles[consk] = _ConsoleHandler(node, configmanager)
#this represents some api view of a console handler.  This handles things like
#holding the caller specific queue data, for example, when http api should be
#sending data, but there is no outstanding POST request to hold it,
# this object has the job of holding the data


class ConsoleSession(object):
    """Create a new socket to converse with node console

    This object provides a filehandle that can be read/written
    too in a normal fashion and the concurrency, logging, and
    event watching will all be handled seamlessly

    :param node: Name of the node for which this session will be created
    """

    def __init__(self, node, configmanager, username, datacallback=None):
        self.tenant = configmanager.tenant
        consk = (node, self.tenant)
        self.ckey = consk
        self.username = username
        connect_node(node, configmanager)
        _handled_consoles[consk].attachuser(username)
        self._evt = None
        self.node = node
        self.conshdl = _handled_consoles[consk]
        self.write = _handled_consoles[consk].write
        if datacallback is None:
            self.reaper = eventlet.spawn_after(15, self.destroy)
            self.databuffer = collections.deque([])
            self.reghdl = _handled_consoles[consk].register_rcpt(self.got_data)
            self.databuffer.extend(_handled_consoles[consk].get_recent())
        else:
            self.reghdl = _handled_consoles[consk].register_rcpt(datacallback)
            for recdata in _handled_consoles[consk].get_recent():
                if recdata:
                    datacallback(recdata)

    def send_break(self):
        self.conshdl.send_break()

    def destroy(self):
        _handled_consoles[self.ckey].detachuser(self.username)
        _handled_consoles[self.ckey].unregister_rcpt(self.reghdl)
        self.databuffer = None
        self._evt = None
        self.reghdl = None

    def got_data(self, data):
        """Receive data from console and buffer

        If the caller does not provide a callback and instead will be polling
        for data, we must maintain data in a buffer until retrieved
        """
        self.databuffer.append(data)
        if self._evt:
            self._evt.send()

    def get_next_output(self, timeout=45):
        """Poll for next available output on this console.

        Ideally purely event driven scheme is perfect.  AJAX over HTTP is
        at least one case where we don't have that luxury
        """
        self.reaper.cancel()
        if self._evt:
            raise Exception('get_next_output is not re-entrant')
        if not self.databuffer:
            self._evt = eventlet.event.Event()
            with eventlet.Timeout(timeout, False):
                self._evt.wait()
            self._evt = None
        if not self.databuffer:
            self.reaper = eventlet.spawn_after(15, self.destroy)
            return ""
        currdata = self.databuffer.popleft()
        if isinstance(currdata, dict):
            self.reaper = eventlet.spawn_after(15, self.destroy)
            return currdata
        retval = currdata
        while self.databuffer and not isinstance(self.databuffer[0], dict):
            retval += self.databuffer.popleft()
        # the client has 15 seconds to make a new request for data before
        # they are given up on
        self.reaper = eventlet.spawn_after(15, self.destroy)
        return retval
