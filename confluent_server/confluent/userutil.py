from ctypes import *
from ctypes.util import find_library
import confluent.util as util
import grp
import pwd
import os
libc = cdll.LoadLibrary(find_library('c'))
_getgrouplist = libc.getgrouplist
_getgrouplist.restype = c_int32


class TooSmallException(Exception):
    def __init__(self, count):
        self.count = count
        super(TooSmallException, self).__init__()


def getgrouplist(name, gid, ng=32):
    _getgrouplist.argtypes = [c_char_p, c_uint, POINTER(c_uint * ng), POINTER(c_int)]
    glist = (c_uint * ng)()
    nglist = c_int(ng)
    if not isinstance(name, bytes):
        name = name.encode('utf-8')
    count = _getgrouplist(name, gid, byref(glist), byref(nglist))
    if count < 0:
        raise TooSmallException(nglist.value)
    for gidx in range(count):
        gent = glist[gidx]
        yield grp.getgrgid(gent).gr_name


def grouplist(username):
    username = util.stringify(username)
    pent = pwd.getpwnam(username)
    try:
        groups = getgrouplist(pent.pw_name, pent.pw_gid)
    except TooSmallException as e:
        groups = getgrouplist(pent.pw_name, pent.pw_gid, e.count)
    return list(groups)

if __name__ == '__main__':
    import sys
    print(repr(grouplist(sys.argv[1])))

