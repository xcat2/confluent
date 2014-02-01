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
        raise NotImplementedException("Subclassing required")

    def connect(self, callback):
        raise NotImplementedException("Subclassing required")

    def write(self, data):
        raise NotImplementedException("Subclassing required")

    def wait_for_data(self, timeout=600):
        raise NotImplementedException("Subclassing required")

