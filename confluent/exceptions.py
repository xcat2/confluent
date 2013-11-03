class ConfluentException(Exception):
    pass

class NotFoundException(ConfluentException):
    pass

class InvalidArgumentException(ConfluentException):
    pass
