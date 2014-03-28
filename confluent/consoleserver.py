# Copyright 2013 IBM Corporation
# All rights reserved

# This is the common console support for confluent.  It takes over
# whatever filehandle is conversing with the client and starts
# relaying data.  It uses Ctrl-] like telnet for escape back to prompt

#we track nodes that are actively being logged, watched, or have attached
#there should be no more than one handler per node
import confluent.interface.console as conapi
import confluent.log as log
import confluent.pluginapi as plugin
import eventlet
import eventlet.green.threading as threading
import random

_handled_consoles = {}


class _ConsoleHandler(object):
    def __init__(self, node, configmanager):
        self.rcpts = {}
        self.cfgmgr = configmanager
        self.node = node
        self.logger = log.Logger(node, tenant=configmanager.tenant)
        self.buffer = bytearray()
        (text, termstate) = self.logger.read_recent_text(8192)
        self.buffer += text
        self.appmodedetected = False
        self.shiftin = None
        if termstate & 1:
            self.appmodedetected = True
        if termstate & 2:
            self.shiftin = '0'
        self._connect()
        self.users = {}


    def _connect(self):
        self._console = plugin.handle_path(
            "/nodes/%s/_console/session" % self.node,
            "create", self.cfgmgr)
        self._console.connect(self.get_console_output)

    def unregister_rcpt(self, handle):
        if handle in self.rcpts:
            del self.rcpts[handle]

    def register_rcpt(self, callback):
        hdl = random.random()
        while hdl in self.rcpts:
            hdl = random.random()
        self.rcpts[hdl] = callback
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
                self._connect()
            return
        prefix = ''
        if '\0' in data:  # there is a null in the output
            # the proper response is to do nothing, but here using it as a cue
            # that perhaps firmware has reset since that's the only place
            # observed so far.  Lose the shiftin and app mode when detected
            prefix = '\x1b[?1l'
            self.shiftin = None
            self.appmodedetected = False
        if '\x1b[?1h' in data:  # remember the session wants the client to be in
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
        for rcpt in self.rcpts.itervalues():
            try:
                rcpt(prefix + data)
            except:
                pass

    def get_recent(self):
        """Retrieve 'recent' data

        Replay data in the intent to perhaps reproduce the display.
        """
        #For now, just try to seek back in buffer to find a clear screen
        #If that fails, just return buffer
        #a scheme always tracking the last clear screen would be too costly
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
            return retdata + str(self.buffer[bufidx:])
        #another scheme is the 2J scheme
        bufidx = self.buffer.rfind('\x1b[2J')
        if bufidx >= 0:
            # there was some sort of clear screen event
            # somewhere in the buffer, replay from that point
            # in hopes that it reproduces the screen
            return retdata + str(self.buffer[bufidx:])
        else:
            #we have no indication of last erase, play back last kibibyte
            #to give some sense of context anyway
            return retdata + str(self.buffer[-1024:])

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
            self.databuffer = _handled_consoles[consk].get_recent()
            self.reghdl = _handled_consoles[consk].register_rcpt(self.got_data)
        else:
            self.reghdl = _handled_consoles[consk].register_rcpt(datacallback)
            recdata = _handled_consoles[consk].get_recent()
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
        self.databuffer += data
        self._evt.set()

    def get_next_output(self, timeout=45):
        """Poll for next available output on this console.

        Ideally purely event driven scheme is perfect.  AJAX over HTTP is
        at least one case where we don't have that luxury
        """
        self.reaper.cancel()
        if len(self.databuffer) == 0:
            self._evt.wait(timeout)
        retval = self.databuffer
        self.databuffer = ""
        if self._evt is not None:
            self._evt.clear()
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
