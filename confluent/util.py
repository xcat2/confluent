# IBM (c) 2013

# Various utility functions that do not neatly fit into one category or another
import base64
import os
import struct


def randomstring(length=20):
    """Generate a random string of requested length

    :param length: The number of characters to produce, defaults to 20
    """
    chunksize = length / 4
    if (length % 4 > 0):
        chunksize += 1
    strval = base64.urlsafe_b64encode(os.urandom(chunksize * 3))
    return strval[0:length-1]


def securerandomnumber(min=0, max=4294967295):
    """Return a random number within requested range

    Note that this function will not return smaller than 0 nor larger
    than 2^32-1 no matter what is requested.
    The python random number facility does not provide charateristics
    appropriate for secure rng, go to os.urandom

    :param min: Smallest number to return (defaults to 0)
    :param max: largest number to return (defaults to 2^32-1)
    """
    number = -1
    while number < min or number > max:
        number = struct.unpack("I", os.urandom(4))[0]
    return number


def monotonic_time():
    """Return a monotoc time value

    In scenarios like timeouts and such, monotonic timing is preferred.
    """
    # for now, just support POSIX systems
    return os.times()[4]
