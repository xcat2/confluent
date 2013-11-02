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

