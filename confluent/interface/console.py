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


class ConsoleEvent(object):
    """This represents a number of specific events to be sent between
    consoleserver and console objects.  Disconnect indicates that the console
    object has lost connection.  The response to this will be to dispose of the
    Console object and try to request a new one, rather than requesting
    reconnect or anything like that.  Break is a serial break."""
    Disconnect, Break = range(2)


class Console(object):
    """This is the class defining the interface a console plugin must return
    for the _console/session element"""
    def __init__(self, node, config):
        raise NotImplementedError("Subclassing required")

    def connect(self, callback):
        raise NotImplementedError("Subclassing required")

    def write(self, data):
        raise NotImplementedError("Subclassing required")

    def wait_for_data(self, timeout=600):
        raise NotImplementedError("Subclassing required")

    def send_break(self):
        """This function is how a plugin should implement sending a break to
        the remote console"""
        pass

    def ping(self):
        """This function is a hint to the console plugin that now would be a
        nice time to assess health of console connection.  Plugins that see
        a use for this should be periodically doing this on their own for
        logging and such, this provides a hint that a user has taken an
        explicit interest in the console output.  In my experience, this
        correlates with some conditions that may suggest a loss of console
        as well, so consoles can schedule a health check to run at this time.
        No return is expected, any error condition can be reported by sending
        ConsoleEvent.Disconnect, just like normal."""
        pass
