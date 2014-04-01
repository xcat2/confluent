class ConfluentException(Exception):
    pass

class NotFoundException(ConfluentException):
    # Something that could be construed as a name was not found
    # basically, picture an http error code 404
    pass

class InvalidArgumentException(ConfluentException):
    # Something from the remote client wasn't correct
    # like http code 400
    pass

class TargetEndpointUnreachable(ConfluentException):
    # A target system was unavailable.  For example, a BMC
    # was unreachable.  http code 504
    pass
