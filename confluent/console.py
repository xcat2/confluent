# Copyright 2013 IBM Corporation
# All rights reserved

# This is the common console support for confluent.  It takes over
# whatever filehandle is conversing with the client and starts
# relaying data.  It uses Ctrl-] like telnet for escape back to prompt

#we track nodes that are actively being logged, watched, or have attached
#there should be no more than one handler per node
import confluent.pluginapi as plugin
import confluent.util as util

_handled_consoles = {}

class _ConsoleHandler(object):
    def __init__(self, node, configmanager):
        self._console = plugin.handle_path("/node/%s/_console/session" % node,
            "create", configmanager)
        self._console.connect(self.get_console_output)
        self.rcpts = []

    def register_rcpt(self, callback):
        self.rcpts.append(callback)

    def get_console_output(self, data):
        #TODO: logging, forwarding, etc
        for rcpt in self.rcpts:
            rcpt(data)

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

    def __init__(self, node, configmanager):
        self.databuffer = ""
        if node not in _handled_consoles:
            _handled_consoles[node] = _ConsoleHandler(node, configmanager)
        self.conshdl = _handled_consoles[node]
        self.write = _handled_consoles[node].write
        _handled_consoles[node].register_rcpt(self.got_data)

    def got_data(self, data):
        self.databuffer += data

    def get_next_output(self, timeout=45):
        """Poll for next available output on this console.

        Ideally purely event driven scheme is perfect.  AJAX over HTTP is
        at least one case where we don't have that luxury
        """
        currtime = util.monotonic_time()
        deadline = currtime + 45
        while len(self.databuffer) == 0 and currtime < deadline:
            timeo = deadline - currtime
            self.conshdl.wait_for_data(timeout=timeo)
            currtime = util.monotonic_time()
        retval = self.databuffer
        self.databuffer = ""
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
