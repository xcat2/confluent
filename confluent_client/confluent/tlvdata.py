# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2014 IBM Corporation
# Copyright 2015 Lenovo
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

import array
import asyncio
import ctypes
import ctypes.util
import confluent.tlv as tlv
import socket
import select
from datetime import datetime
import json
import os
import struct

try:
    unicode
except NameError:
    unicode = str

try:
    range = xrange
except NameError:
    pass


class iovec(ctypes.Structure):   # from uio.h
    _fields_ = [('iov_base', ctypes.c_void_p),
                ('iov_len', ctypes.c_size_t)]


iovec_ptr = ctypes.POINTER(iovec)


class cmsghdr(ctypes.Structure):  # also from bits/socket.h
    _fields_ = [('cmsg_len', ctypes.c_size_t),
                ('cmsg_level', ctypes.c_int),
                ('cmsg_type', ctypes.c_int)]

    @classmethod
    def init_data(cls, cmsg_len, cmsg_level, cmsg_type, cmsg_data):
        Data = ctypes.c_ubyte * ctypes.sizeof(cmsg_data)

        class _flexhdr(ctypes.Structure):
            _fields_ = cls._fields_ + [('cmsg_data', Data)]

        datab = Data(*bytearray(cmsg_data))
        return _flexhdr(cmsg_len=cmsg_len, cmsg_level=cmsg_level,
                        cmsg_type=cmsg_type, cmsg_data=datab)


def CMSG_LEN(length):
    sizeof_cmshdr = ctypes.sizeof(cmsghdr)
    return ctypes.c_size_t(CMSG_ALIGN(sizeof_cmshdr).value + length)


SCM_RIGHTS = 1


class msghdr(ctypes.Structure):  # from bits/socket.h
    _fields_ = [('msg_name', ctypes.c_void_p),
                ('msg_namelen', ctypes.c_uint),
                ('msg_iov', ctypes.POINTER(iovec)),
                ('msg_iovlen', ctypes.c_size_t),
                ('msg_control', ctypes.c_void_p),
                ('msg_controllen', ctypes.c_size_t),
                ('msg_flags', ctypes.c_int)]


def CMSG_ALIGN(length):  # bits/socket.h
    ret = (length + ctypes.sizeof(ctypes.c_size_t) - 1
           & ~(ctypes.sizeof(ctypes.c_size_t) - 1))
    return ctypes.c_size_t(ret)


def CMSG_SPACE(length):  # bits/socket.h
    ret = CMSG_ALIGN(length).value + CMSG_ALIGN(ctypes.sizeof(cmsghdr)).value
    return ctypes.c_size_t(ret)


class ClientFile(object):
    def __init__(self, name, mode, fd):
        self.fileobject = os.fdopen(fd, mode)
        self.filename = name

libc = ctypes.CDLL(ctypes.util.find_library('c'))
recvmsg = libc.recvmsg
recvmsg.argtypes = [ctypes.c_int, ctypes.POINTER(msghdr), ctypes.c_int]
recvmsg.restype = ctypes.c_int


def _sendmsg(loop, fut, sock, msg, fds, rfd):
    if rfd is not None:
        loop.remove_reader(rfd)
    if fut.cancelled():
        return
    try:
        retdata = sock.sendmsg([msg], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))])
    except (BlockingIOError, InterruptedError):
        fd = sock.fileno()
        loop.add_reader(fd, _sendmsg, loop, fut, sock, fd)
    except Exception as exc:
        fut.set_exception(exc)
    else:
        fut.set_result(retdata)


def send_fds(sock, msg, fds):
    cloop = asyncio.get_event_loop()
    fut = cloop.create_future()
    _sendmsg(cloop, fut, sock, msg, fds, None)
    return fut


def _recvmsg(loop, fut, sock, msglen, maxfds, rfd):
    if rfd is not None:
        loop.remove_reader(rfd)
    fds = array.array("i")   # Array of ints
    try:
        msg, ancdata, flags, addr = sock.recvmsg(
            msglen, socket.CMSG_LEN(maxfds * fds.itemsize))
    except (BlockingIOError, InterruptedError):
        fd = sock.fileno()
        loop.add_reader(fd, _recvmsg, loop, fut, sock, fd)
    except Exception as exc:
        fut.set_exception(exc)
    else:
        for cmsg_level, cmsg_type, cmsg_data in ancdata:
            if (cmsg_level == socket.SOL_SOCKET
                    and cmsg_type == socket.SCM_RIGHTS):
                # Append data, ignoring any truncated integers at the end.
                fds.frombytes(
                    cmsg_data[
                        :len(cmsg_data) - (len(cmsg_data) % fds.itemsize)])
        fut.set_result(msglen, list(fds))

def recv_fds(sock, msglen, maxfds):
    cloop = asyncio.get_event_loop()
    fut = cloop.create_future()
    _recvmsg(cloop, fut, sock, msglen, maxfds, None)
    return fut


def decodestr(value):
    ret = None
    try:
        ret = value.decode('utf-8')
    except UnicodeDecodeError:
        try:
            ret = value.decode('cp437')
        except UnicodeDecodeError:
            ret = value
    except AttributeError:
        return value
    return ret

def unicode_dictvalues(dictdata):
    for key in dictdata:
        if isinstance(dictdata[key], bytes):
            dictdata[key] = decodestr(dictdata[key])
        elif isinstance(dictdata[key], datetime):
            dictdata[key] = dictdata[key].strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(dictdata[key], list):
            _unicode_list(dictdata[key])
        elif isinstance(dictdata[key], dict):
            unicode_dictvalues(dictdata[key])


def _unicode_list(currlist):
    for i in range(len(currlist)):
        if isinstance(currlist[i], str):
            currlist[i] = decodestr(currlist[i])
        elif isinstance(currlist[i], dict):
            unicode_dictvalues(currlist[i])
        elif isinstance(currlist[i], list):
            _unicode_list(currlist[i])


async def send(handle, data, filehandle=None):
    cloop = asyncio.get_event_loop()
    if isinstance(data, unicode):
        try:
            data = data.encode('utf-8')
        except AttributeError:
            pass
    if isinstance(data, bytes) or isinstance(data, unicode):
        # plain text, e.g. console data
        tl = len(data)
        if tl == 0:
            # if you don't have anything to say, don't say anything at all
            return
        if tl < 16777216:
            # type for string is '0', so we don't need
            # to xor anything in
            await cloop.sock_sendall(handle, struct.pack("!I", tl))
        else:
            raise Exception("String data length exceeds protocol")
        await cloop.sock_sendall(handle, data)
    elif isinstance(data, dict):  # JSON currently only goes to 4 bytes
        # Some structured message, like what would be seen in http responses
        unicode_dictvalues(data)  # make everything unicode, assuming UTF-8
        sdata = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
        sdata = sdata.encode('utf-8')
        tl = len(sdata)
        if tl > 16777215:
            raise Exception("JSON data exceeds protocol limits")
        # xor in the type (0b1 << 24)
        if filehandle is None:
            tl |= 16777216
            await cloop.sock_sendall(handle, struct.pack("!I", tl))
            await cloop.sock_sendall(handle, sdata)
        else:
            tl |= (2 << 24)
            await cloop.sock_sendall(handle, struct.pack("!I", tl))
            await send_fds(handle, b'', [filehandle])


async def recvall(handle, size):
    cloop = asyncio.get_event_loop()
    rd = await cloop.sock_recv(handle, size)
    while len(rd) < size:
        nd = await cloop.sock_recv(handle, size - len(rd))
        if not nd:
            raise Exception("Error reading data")
        rd += nd
    return rd


async def recv(handle):
    cloop = asyncio.get_event_loop()
    tl = await cloop.sock_recv(handle, 4)
    if not tl:
        return None
    while len(tl) < 4:
        ndata = await cloop.sock_recv(handle, 4 - len(tl))
        if not ndata:
            raise Exception("Error reading data")
        tl += ndata
    if len(tl) == 0:
        return None
    tl = struct.unpack("!I", tl)[0]
    if tl & 0b10000000000000000000000000000000:
        raise Exception("Protocol Violation, reserved bit set")
    # 4 byte tlv
    dlen = tl & 16777215  # grab lower 24 bits
    datatype = (tl & 2130706432) >> 24  # grab 7 bits from near beginning
    if dlen == 0:
        return None
    if datatype == tlv.Types.filehandle:
        filehandles = array.array('i')
        rawbuffer = bytearray(2048)
        pkttype = ctypes.c_ubyte * 2048
        data = pkttype.from_buffer(rawbuffer)
        cmsgsize = CMSG_SPACE(ctypes.sizeof(ctypes.c_int)).value
        cmsgarr = bytearray(cmsgsize)
        cmtype = ctypes.c_ubyte * cmsgsize
        cmsg = cmtype.from_buffer(cmsgarr)
        cmsg.cmsg_level = socket.SOL_SOCKET
        cmsg.cmsg_type = SCM_RIGHTS
        cmsg.cmsg_len = CMSG_LEN(ctypes.sizeof(ctypes.c_int))
        iov = iovec()
        iov.iov_base = ctypes.addressof(data)
        iov.iov_len = 2048
        msg = msghdr()
        msg.msg_iov = ctypes.pointer(iov)
        msg.msg_iovlen = 1
        msg.msg_control = ctypes.addressof(cmsg)
        msg.msg_controllen = ctypes.sizeof(cmsg)
        i = await recv_fds(handle, 2048, 4)
        print(repr(i))
        data = i[0]
        filehandles = i[1]
        data = json.loads(bytes(data))
        return ClientFile(data['filename'], data['mode'], filehandles[0])
    else:
        data = await cloop.sock_recv(handle, dlen)
        while len(data) < dlen:
            ndata = await cloop.sock_recv(handle, dlen - len(data))
            if not ndata:
                raise Exception("Error reading data")
            data += ndata
    if datatype == tlv.Types.text:
        return data
    elif datatype == tlv.Types.json:
        return json.loads(data)
