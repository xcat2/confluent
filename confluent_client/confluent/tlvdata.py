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

import confluent.tlv as tlv
from datetime import datetime
import json
import struct

try:
    unicode
except NameError:
    unicode = str

def decodestr(value):
    ret = None
    try:
        ret = value.decode('utf-8')
    except UnicodeDecodeError:
        try:
            ret = value.decode('cp437')
        except UnicodeDecodeError:
            ret = value
    return ret

def unicode_dictvalues(dictdata):
    for key in dictdata:
        if isinstance(dictdata[key], str):
            dictdata[key] = decodestr(dictdata[key])
        elif isinstance(dictdata[key], datetime):
            dictdata[key] = dictdata[key].strftime('%Y-%m-%dT%H:%M:%S')
        elif isinstance(dictdata[key], list):
            _unicode_list(dictdata[key])
        elif isinstance(dictdata[key], dict):
            unicode_dictvalues(dictdata[key])


def _unicode_list(currlist):
    for i in xrange(len(currlist)):
        if isinstance(currlist[i], str):
            currlist[i] = decodestr(currlist[i])
        elif isinstance(currlist[i], dict):
            unicode_dictvalues(currlist[i])
        elif isinstance(currlist[i], list):
            _unicode_list(currlist[i])


def send(handle, data):
    if isinstance(data, str) or isinstance(data, unicode):
        try:
            data = data.encode('utf-8')
        except AttributeError:
            pass
        # plain text, e.g. console data
        tl = len(data)
        if tl == 0:
            # if you don't have anything to say, don't say anything at all
            return
        if tl < 16777216:
            # type for string is '0', so we don't need
            # to xor anything in
            handle.sendall(struct.pack("!I", tl))
        else:
            raise Exception("String data length exceeds protocol")
        handle.sendall(data)
    elif isinstance(data, dict):  # JSON currently only goes to 4 bytes
        # Some structured message, like what would be seen in http responses
        unicode_dictvalues(data)  # make everything unicode, assuming UTF-8
        sdata = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
        sdata = sdata.encode('utf-8')
        tl = len(sdata)
        if tl > 16777215:
            raise Exception("JSON data exceeds protocol limits")
        # xor in the type (0b1 << 24)
        tl |= 16777216
        handle.sendall(struct.pack("!I", tl))
        handle.sendall(sdata)

def recvall(handle, size):
    rd = handle.recv(size)
    while len(rd) < size:
        nd = handle.recv(size - len(rd))
        if not nd:
            raise Exception("Error reading data")
        rd += nd
    return rd

def recv(handle):
    tl = handle.recv(4)
    if not tl:
        return None
    while len(tl) < 4:
        ndata = handle.recv(4 - len(tl))
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
    data = handle.recv(dlen)
    while len(data) < dlen:
        ndata = handle.recv(dlen - len(data))
        if not ndata:
            raise Exception("Error reading data")
        data += ndata
    if datatype == tlv.Types.text:
        return data
    elif datatype == tlv.Types.json:
        return json.loads(data)
