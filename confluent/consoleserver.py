# Copyright 2013 IBM Corporation
# All rights reserved

# This is the common console support for confluent.  It takes over
# whatever filehandle is conversing with the client and starts
# relaying data.  It uses Ctrl-] like telnet for escape back to prompt

#we track nodes that are actively being logged, watched, or have attached
#there should be no more than one handler per node
import collections
import confluent.exceptions as exc
import confluent.interface.console as conapi
import confluent.log as log
import confluent.pluginapi as plugin
import eventlet
import eventlet.green.threading as threading
import random

_handled_consoles = {}

_genwatchattribs = frozenset(('console.method',))


class _ConsoleHandler(object):
    def __init__(self, node, configmanager):
        self.rcpts = {}
        self.cfgmgr = configmanager
        self.node = node
        self.connectstate = 'unconnected'
        self.clientcount = 0
        self.logger = log.Logger(node, tenant=configmanager.tenant)
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
        self.connectstate = 'connecting'
        self._attribwatcher = None
        self._console = None
        self.connectionthread = None
        eventlet.spawn(self._connect)

    def _attribschanged(self, **kwargs):
        eventlet.spawn(self._connect)

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
        self._console = plugin.handle_path(
            "/nodes/%s/_console/session" % self.node,
            "create", self.cfgmgr)
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
        except exc.TargetEndpointUnreachable:
            self.connectstate = 'unconnected'
            self._send_rcpts({'connectstate': self.connectstate})
            retrytime = 30 + (30 * random.random())
            if not self.reconnect:
                self.reconnect = eventlet.spawn_after(retrytime, self._connect)
            return
        self._got_connected()

    def _got_connected(self):
        self.connectstate = 'connected'
        self._send_rcpts({'connectstate': self.connectstate})

    def _got_disconnected(self):
        self.connecstate = 'unconnected'
        eventlet.spawn(self._send_disconnect_events)
        self._send_rcpts({'connectstate': self.connectstate})
        self._connect()

    def unregister_rcpt(self, handle):
        self.clientcount -= 1
        if handle in self.rcpts:
            del self.rcpts[handle]
        self._send_rcpts({'clientcount': self.clientcount})

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
        self.logger.log(
            logdata=username, ltype=log.DataTypes.event,
            event=log.Events.clientconnect, eventdata=edata)

    def detachuser(self, username):
        self.users[username] -= 1
        if self.users[username] < 2:
            edata = self.users[username]
        else:
            edata = 2
        self.logger.log(
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
            eventdata = eventdata | 1
        if self.shiftin is not None:
            eventdata = eventdata | 2
        self.logger.log(data, eventdata=eventdata)
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
            except:
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
        if self.shiftin is not None:  #detected that terminal requested a
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
            return (retdata + str(self.buffer[bufidx:]), connstate)
        #another scheme is the 2J scheme
        bufidx = self.buffer.rfind('\x1b[2J')
        if bufidx >= 0:
            # there was some sort of clear screen event
            # somewhere in the buffer, replay from that point
            # in hopes that it reproduces the screen
            return (retdata + str(self.buffer[bufidx:]), connstate)
        else:
            #we have no indication of last erase, play back last kibibyte
            #to give some sense of context anyway
            return (retdata + str(self.buffer[-1024:]), connstate)

    def write(self, data):
        #TODO.... take note of data coming in from audit/log perspective?
        #or just let echo take care of it and then we can skip this stack
        #level?
        self._console.write(data)


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
        self._evt = threading.Event()
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
            for recdata in  _handled_consoles[consk].get_recent():
                if recdata:
                    datacallback(recdata)

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
        self._evt.set()

    def get_next_output(self, timeout=45):
        """Poll for next available output on this console.

        Ideally purely event driven scheme is perfect.  AJAX over HTTP is
        at least one case where we don't have that luxury
        """
        self.reaper.cancel()
        if not self.databuffer:
            self._evt.wait(timeout)
        if self._evt is not None:
            self._evt.clear()
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


def handle_request(request=None, connection=None, releaseconnection=False):
    """
    Process a request from confluent.

    :param request: For 'datagram' style console, this represents a wait for
                    data or input.
    :param connection: For socket style console, this is a read/write socket
                       that the caller has released from it's control and
                       console plugin will do all IO
    :param releaseconnection: A function for console to call to indicate
                          confluent should resume control over the connection

    """
    if request is not None:  # This is indicative of http style
        pass  # TODO(jbjohnso): support AJAX style interaction.
              # a web ui looking to actually take advantage will
              # probably have to pull in the GPL javascript
              # from shellinabox or something similar
              # the way that works is URI encoded input with width, heiht,
              # session or rooturl:opening
              # opening session
              # width=120&height=24&rooturl=/nodes/n1/console/session
              # making a request to wait for data:
              # width=120&height=24&session=blahblahblah
              # <hitting enter>:
              # width=120&height=24&session=blahblahblah&keys=0D
              # pasting 'rabbit'
              # width=120&height=24&session=blahblah&keys=726162626974
              # if no client session indicated, it expects some session number
              # in return.
              # the responses:
              # <responding to session open>: (the session seems to be opaque
              # {"session":"h5lrOKViIeQGp1nXjKWpAQ","data":""}
              # <responding to wait for data with data, specically a prompt
              # that sets title>
              # {"session":"blah","data":"\r\n\u001B]0;bob@thor:~\u0007$ "}
              # <responding to wait with no data (seems to wait 46 seconds)
              # {"session":"jSGBPmAxavsD/1acSl/uog","data":""}
              # closed session returns HTTP 400 to a console answer
    elif connection is not None:  # This is a TLS or unix socket
        ConsoleSession(connection, releaseconnection)
