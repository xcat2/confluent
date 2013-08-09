# IBM (c) 2013

# Various utility functions that do not neatly fit into one category or another
import base64
import os

def randomstring(length=20):
    """Generate a random string of requested length

    :param length: The number of characters to produce, defaults to 20
    """
    chunksize = length / 4
    if (length % 4 > 0):
        chunksize += 1
    strval = base64.urlsafe_b64encode(os.urandom(chunksize * 3))
    return strval[0:length-1]
