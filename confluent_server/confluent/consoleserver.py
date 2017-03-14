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

# we track nodes that are actively being logged, watched, or have attached
# there should be no more than one handler per node
import collections
import confluent.config.configmanager as configmodule
import confluent.exceptions as exc
import confluent.interface.console as conapi
import confluent.log as log
import confluent.core as plugin
import confluent.util as util
import eventlet
import eventlet.event
import pyte
import random
import time
import traceback

_handled_consoles = {}

_tracelog = None


pytecolors2ansi = {
    'black': 0,
    'red': 1,
    'green': 2,
    'brown': 3,
    'blue': 4,
    'magenta': 5,
    'cyan': 6,
    'white': 7,
    'default': 9,
}

def pytechars2line(chars):
    # _Char(data=u' ', fg='white', bg='blue', bold=True, italics=False, underscore=False, strikethrough=False, reverse=False)

    line = '\x1b[m'  # start at default params
    lb = False  # last bold
    li = False  # last italic
    lu = False  # last underline
    ls = False  # last strikethrough
    lr = False  # last reverse
    lfg = 'default'  # last fg color
    lbg = 'default'   # last bg color
    hasdata = False
    for char in chars:
        csi = []
        if char.fg != lfg:
            csi.append(30 + pytecolors2ansi[char.fg])
            lfg = char.fg
        if char.bg != lbg:
            csi.append(40 + pytecolors2ansi[char.bg])
            lbg = char.bg
        if char.bold != lb:
            lb = char.bold
            csi.append(1 if lb else 22)
        if char.italics != li:
            li = char.italics
            csi.append(3 if li else 23)
        if char.underscore != lu:
            lu = char.underscore
            csi.append(4 if lu else 24)
        if char.strikethrough != ls:
            ls = char.strikethrough
            csi.append(9 if ls else 29)
        if char.reverse != lr:
            lr = char.reverse
            csi.append(7 if lr else 27)
        if csi:
            line += b'\x1b[' + b';'.join(['{0}'.format(x) for x in csi]) + b'm'
        if char.data.encode('utf-8').rstrip():
            hasdata = True
        line += char.data.encode('utf-8')
    line = line.rstrip()
    return line, hasdata


class ConsoleHandler(object):
    _plugin_path = '/nodes/{0}/_console/session'
    _logtobuffer = True
    _genwatchattribs = frozenset(('console.method', 'console.logging'))

    def __init__(self, node, configmanager):
        self._dologging = True
        self._isondemand = False
        self.error = None
        self.cfgmgr = configmanager
        self.node = node
        self.connectstate = 'unconnected'
        self._isalive = True
        self.buffer = pyte.Screen(100, 31)
        self.termstream = pyte.ByteStream()
        self.termstream.attach(self.buffer)
        self.livesessions = set([])
        if self._logtobuffer:
            self.logger = log.Logger(node, console=True,
                                     tenant=configmanager.tenant)
            (text, termstate, timestamp) = self.logger.read_recent_text(8192)
        else:
            (text, termstate, timestamp) = ('', 0, False)
        # when reading from log file, we will use wall clock
        # it should usually match walltime.
        self.lasttime = 0
        if timestamp:
            timediff = time.time() - timestamp
            if timediff > 0:
                self.lasttime = util.monotonic_time() - timediff
            else:
                # wall clock has gone backwards, use current time as best
                # guess
                self.lasttime = util.monotonic_time()
        self.termstream.feed(text)
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
        if self._genwatchattribs:
            self._attribwatcher = self.cfgmgr.watch_attributes(
                (self.node,), self._genwatchattribs, self._attribschanged)
        self.check_isondemand()
        if not self._isondemand:
            self.connectstate = 'connecting'
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

    def get_buffer_age(self):
        """Return age of buffered data

        Returns age in seconds of the buffered data or
        False in the event of calling before buffered data"""
        if self.lasttime:
            return util.monotonic_time() - self.lasttime
        return False

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
                # if the *only* thing to change is the log,
                # then let always on handle reconnect if needed,
                # since we want to avoid a senseless disconnect
                # if already connected
                # if other things change, then unconditionally reconnect
                onlylogging = len(nodeattribs[self.node]) == 1
                self._alwayson(doconnect=onlylogging)
                if onlylogging:
                    return
            else:
                self._ondemand()
                if logvalue == 'none':
                    self._dologging = False
        if not self._isondemand or self.livesessions:
            eventlet.spawn(self._connect)

    def log(self, *args, **kwargs):
        if not self._dologging:
            return
        self.logger.log(*args, **kwargs)

    def _alwayson(self, doconnect=True):
        self._isondemand = False
        if not doconnect:
            return
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
        if not self.livesessions and self._console:
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
                self._plugin_path.format(self.node),
                "create", self.cfgmgr)
        except exc.NotImplementedException:
            self._console = None
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
            attribstowatch = self._console.configattributes | self._genwatchattribs
        else:
            attribstowatch = self._genwatchattribs
        if self._genwatchattribs:
            self._attribwatcher = self.cfgmgr.watch_attributes(
                (self.node,), attribstowatch, self._attribschanged)
        try:
            self._console.connect(self.get_console_output)
        except exc.TargetEndpointBadCredentials:
            self.error = 'badcredentials'
            self.connectstate = 'unconnected'
            self._send_rcpts({'connectstate': self.connectstate,
                              'error': self.error})
            retrytime = 120 + (120 * random.random())
            if not self.reconnect:
                self.reconnect = eventlet.spawn_after(retrytime, self._connect)
            return
        except exc.TargetEndpointUnreachable:
            self.error = 'unreachable'
            self.connectstate = 'unconnected'
            self._send_rcpts({'connectstate': self.connectstate,
                              'error': self.error})
            retrytime = 120 + (120 * random.random())
            if not self.reconnect:
                self.reconnect = eventlet.spawn_after(retrytime, self._connect)
            return
        except Exception:
            _tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                          event=log.Events.stacktrace)
            self.error = 'unknown'
            self.connectstate = 'unconnected'
            self._send_rcpts({'connectstate': self.connectstate,
                              'error': self.error})
            retrytime = 120 + (120 * random.random())
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
        if self.connectstate != 'unconnected':
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

    def get_console_output(self, data):
        # Spawn as a greenthread, return control as soon as possible
        # to the console object
        eventlet.spawn(self._handle_console_output, data)

    def attachsession(self, session):
        edata = 1
        for currsession in self.livesessions:
            if currsession.username == session.username:
                # indicate that user has multiple connections
                edata = 2
        self.livesessions.add(session)
        self.log(
            logdata=session.username, ltype=log.DataTypes.event,
            event=log.Events.clientconnect, eventdata=edata)
        self._send_rcpts({'clientcount': len(self.livesessions)})
        if self.connectstate == 'unconnected':
            # if console is not connected, take time to try to assert
            # connectivity now.
            if self.reconnect:
                # cancel an automated retry if one is pending
                self.reconnect.cancel()
                self.reconnect = None
            self.connectstate = 'connecting'
            eventlet.spawn(self._connect)



    def detachsession(self, session):
        edata = 0
        self.livesessions.discard(session)
        for currsession in self.livesessions:
            if currsession.username == session.username:
                edata += 1
            if edata > 1:  # don't bother counting beyond 2 in the log
                break
        self.log(
            logdata=session.username, ltype=log.DataTypes.event,
            event=log.Events.clientdisconnect, eventdata=edata)
        self._send_rcpts({'clientcount': len(self.livesessions)})
        if self._isondemand and not self.livesessions:
            self._disconnect()


    def reopen(self):
        self._got_disconnected()

    def _handle_console_output(self, data):
        if type(data) == int:
            if data == conapi.ConsoleEvent.Disconnect:
                self._got_disconnected()
            return
        elif data == '':
            # ignore empty strings from a cconsole provider
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
        self.lasttime = util.monotonic_time()
        self.termstream.feed(data)
        # TODO: analyze buffer for registered events, examples:
        #   panics
        #   certificate signing request
        self._send_rcpts(data)

    def _send_rcpts(self, data):
        for rcpt in self.livesessions:
            try:
                rcpt.data_handler(data)
            except:  # No matter the reason, advance to next recipient
                _tracelog.log(traceback.format_exc(), ltype=log.DataTypes.event,
                          event=log.Events.stacktrace)

    def get_recent(self):
        """Retrieve 'recent' data

        Replay data in the intent to perhaps reproduce the display.
        """
        # For now, just try to seek back in buffer to find a clear screen
        # If that fails, just return buffer
        # a scheme always tracking the last clear screen would be too costly
        connstate = {
            'connectstate': self.connectstate,
            'clientcount': len(self.livesessions),
        }
        retdata = b'\x1b[H\x1b[J'  # clear screen
        pendingbl = b''  # pending blank lines
        for line in self.buffer.buffer:
            nline, notblank = pytechars2line(line)
            if notblank:
                if pendingbl:
                    retdata += pendingbl
                    pendingbl = b''
                retdata += nline + '\r\n'
            else:
                pendingbl += nline + '\r\n'
        if self.shiftin is not None:  # detected that terminal requested a
            # shiftin character set, relay that to the terminal that cannected
            retdata += '\x1b)' + self.shiftin
        if self.appmodedetected:
            retdata += '\x1b[?1h'
        else:
            retdata += '\x1b[?1l'
        return retdata, connstate
        return '\x1b[H\x1b[J' + "\r\n".join(self.buffer.display).encode(
            'utf-8'), connstate
        retdata = ''
        if self.shiftin is not None:  # detected that terminal requested a
            # shiftin character set, relay that to the terminal that cannected
            retdata += '\x1b)' + self.shiftin
        if self.appmodedetected:
            retdata += '\x1b[?1h'
        else:
            retdata += '\x1b[?1l'
        # an alternative would be to emulate a VT100 to know what the
        # whole screen would look like
        # this is one scheme to clear screen, move cursor then clear
        bufidx = self.buffer.rfind('\x1b[H\x1b[J')
        if bufidx >= 0:
            return retdata + str(self.buffer[bufidx:]), connstate
        # another scheme is the 2J scheme
        bufidx = self.buffer.rfind('\x1b[2J')
        if bufidx >= 0:
            # there was some sort of clear screen event
            # somewhere in the buffer, replay from that point
            # in hopes that it reproduces the screen
            return retdata + str(self.buffer[bufidx:]), connstate
        else:
            # we have no indication of last erase, play back last kibibyte
            #  to give some sense of context anyway
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


def connect_node(node, configmanager, username=None):
    consk = (node, configmanager.tenant)
    if consk not in _handled_consoles:
        _handled_consoles[consk] = ConsoleHandler(node, configmanager)
    return _handled_consoles[consk]

# this represents some api view of a console handler.  This handles things like
# holding the caller specific queue data, for example, when http api should be
# sending data, but there is no outstanding POST request to hold it,
# this object has the job of holding the data


class ConsoleSession(object):
    """Create a new socket to converse with node console

    This object provides a filehandle that can be read/written
    too in a normal fashion and the concurrency, logging, and
    event watching will all be handled seamlessly

    :param node: Name of the node for which this session will be created
    :param configmanager: A configuration manager object for current context
    :param username: Username for which this session object will operate
    :param datacallback: An asynchronous data handler, to be called when data
                         is available.  Note that if passed, it makes
                         'get_next_output' non-functional
    :param skipreplay: If true, will skip the attempt to redraw the screen
    """
    connector = connect_node

    def __init__(self, node, configmanager, username, datacallback=None,
                 skipreplay=False):
        self.registered = False
        self.tenant = configmanager.tenant
        if not configmanager.is_node(node):
            raise exc.NotFoundException("Invalid node")
        self.username = username
        self.node = node
        self.configmanager = configmanager
        self.connect_session()
        self.registered = True
        self._evt = None
        self.node = node
        self.write = self.conshdl.write
        if datacallback is None:
            self.reaper = eventlet.spawn_after(15, self.destroy)
            self.databuffer = collections.deque([])
            self.data_handler = self.got_data
            if not skipreplay:
                self.databuffer.extend(self.conshdl.get_recent())
        else:
            self.data_handler = datacallback
            if not skipreplay:
                for recdata in self.conshdl.get_recent():
                    if recdata:
                        datacallback(recdata)
        self.conshdl.attachsession(self)


    def connect_session(self):
        """Connect to the appropriate backend handler

        This is not intended to be called by your usual consumer,
        it is a hook for confluent to abstract the concept of a terminal
        between console and shell.
        """
        self.conshdl = connect_node(self.node, self.configmanager,
                                    self.username)
    def send_break(self):
        """Send break to remote system
        """
        self.conshdl.send_break()

    def get_buffer_age(self):
        """Get the age in seconds of the buffered data

        Returns False if no data buffered yet"""
        return self.conshdl.get_buffer_age()

    def reopen(self):
        """Reopen the session

        This can be useful if there is suspicion that the remote console is
        dead.  Note that developers should consider need for this a bug unless
        there really is some fundamental, unavoidable limitation regarding
        automatically detecting an unusable console in the underlying
        technology that cannot be unambiguously autodetected.
        """
        self.conshdl.reopen()

    def destroy(self):
        if self.registered:
            self.conshdl.detachsession(self)
        if self._evt:
            self._evt.send()
        self._evt = None
        self.reghdl = None

    def got_data(self, data):
        """Receive data from console and buffer

        If the caller does not provide a callback and instead will be polling
        for data, we must maintain data in a buffer until retrieved.  This is
        an internal function used as a means to convert the async behavior to
        polling for consumers that cannot do the async behavior.
        """
        self.databuffer.append(data)
        if self._evt:
            self._evt.send()
            self._evt = None

    def get_next_output(self, timeout=45):
        """Poll for next available output on this console.

        Ideally purely event driven scheme is perfect.  AJAX over HTTP is
        at least one case where we don't have that luxury.  This function
        will not work if the session was initialized with a data callback
        instead of polling mode.
        """
        self.reaper.cancel()
        # postpone death to be 15 seconds after this would timeout
        self.reaper = eventlet.spawn_after(timeout + 15, self.destroy)
        if self._evt:
            raise Exception('get_next_output is not re-entrant')
        if not self.databuffer:
            self._evt = eventlet.event.Event()
            with eventlet.Timeout(timeout, False):
                self._evt.wait()
            self._evt = None
        if not self.databuffer:
            return ""
        currdata = self.databuffer.popleft()
        if isinstance(currdata, dict):
            return currdata
        retval = currdata
        while self.databuffer and not isinstance(self.databuffer[0], dict):
            retval += self.databuffer.popleft()

        return retval
