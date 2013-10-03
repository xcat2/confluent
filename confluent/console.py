# Copyright 2013 IBM Corporation
# All rights reserved

# This is the common console support for confluent.  It takes over
# whatever filehandle is conversing with the client and starts
# relaying data.  It uses Ctrl-] like telnet for escape back to prompt

#we track nodes that are actively being logged, watched, or have attached
#there should be no more than one handler per node
import confluent.pluginapi as plugin
import confluent.util as util
import eventlet
import random

_handled_consoles = {}

class _ConsoleHandler(object):
    def __init__(self, node, configmanager):
        self._console = plugin.handle_path("/node/%s/_console/session" % node,
            "create", configmanager)
        self.buffer = bytearray()
        self._console.connect(self.get_console_output)
        self.rcpts = {}

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
        #TODO:log the old stuff
        if len(self.buffer) > 1024:
            self.buffer = bytearray(self.buffer[-1024:])
        #Will be interesting to keep track of logged but
        #retained data, must only log data not already
        #flushed
        #also, timestamp data...

    def get_console_output(self, data):
        self.buffer += data
        #TODO: analyze buffer for registered events, examples:
        #   panics
        #   certificate signing request
        if len(self.buffer) > 8192:
            #call to function to get generic data to log if applicable
            #and shrink buffer
            self.flushbuffer()
        for rcpt in self.rcpts.itervalues():
            rcpt(data)

    def get_recent(self):
        """Retrieve 'recent' data

        Replay data in the intent to perhaps reproduce the display.
        """
        #For now, just try to seek back in buffer to find a clear screen
        #If that fails, just return buffer
        #a scheme always tracking the last clear screen would be too costly
        #an alternative would be to emulate a VT100 to know what the
        #whole screen would look like
        #this is one scheme to clear screen, move cursor then clear
        bufidx = self.buffer.rfind('\x1b[H\x1b[J')
        if bufidx >= 0:
            return str(self.buffer[bufidx:])
        #another scheme is the 2J scheme
        bufidx = self.buffer.rfind('\x1b[2J')
        if bufidx >= 0:
            # there was some sort of clear screen event
            # somewhere in the buffer, replay from that point
            # in hopes that it reproduces the screen
            return str(self.buffer[bufidx:])
        else:
            #we have no indication of last erase, play back last kibibyte
            #to give some sense of context anyway
            return str(self.buffer[-1024:])

    def write(self, data):
        #TODO.... take note of data coming in from audit/log perspective?
        #or just let echo take care of it and then we can skip this stack
        #level?
        self._console.write(data)

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

    def __init__(self, node, configmanager, datacallback=None):
        if node not in _handled_consoles:
            _handled_consoles[node] = _ConsoleHandler(node, configmanager)
        self.node = node
        self.conshdl = _handled_consoles[node]
        self.write = _handled_consoles[node].write
        if datacallback is None:
            self.reaper = eventlet.spawn_after(15, self.destroy)
            self.databuffer =  _handled_consoles[node].get_recent()
            self.reghdl = _handled_consoles[node].register_rcpt(self.got_data)
        else:
            self.reghdl = _handled_consoles[node].register_rcpt(datacallback)
            datacallback(_handled_consoles[node].get_recent())

    def destroy(self):
        _handled_consoles[self.node].unregister_rcpt(self.reghdl)
        self.databuffer = None
        self.reghdl = None

    def got_data(self, data):
        """Receive data from console and buffer

        If the caller does not provide a callback and instead will be polling
        for data, we must maintain data in a buffer until retrieved
        """
        self.databuffer += data

    def get_next_output(self, timeout=45):
        """Poll for next available output on this console.

        Ideally purely event driven scheme is perfect.  AJAX over HTTP is
        at least one case where we don't have that luxury
        """
        self.reaper.cancel()
        currtime = util.monotonic_time()
        deadline = currtime + 45
        if self.databuffer is None:
            return ""
        while len(self.databuffer) == 0 and currtime < deadline:
            timeo = deadline - currtime
            self.conshdl._console.wait_for_data(timeout=timeo)
            currtime = util.monotonic_time()
        retval = self.databuffer
        self.databuffer = ""
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
    :param releaseconnection: A function for console to call to indicate confluent
                          should resume control over the connection

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
              # <responding to wait for data with data, specically a prompt that sets title>
              # {"session":"blah","data":"\r\n\u001B]0;bob@thor:~\u0007[bob@thor ~]$ "}
              # <responding to wait with no data (seems to wait 46 seconds)
              # {"session":"jSGBPmAxavsD/1acSl/uog","data":""}
              # closed session returns HTTP 400 to a console answer
    elif connection is not None:  # This is a TLS or unix socket
        conshandler = ConsoleSession(connection, releaseconnection)
