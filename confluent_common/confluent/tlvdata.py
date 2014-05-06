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

import confluent.common.tlv as tlv
import json
import struct


def send(handle, data):
    if isinstance(data, str):
        # plain text, e.g. console data
        tl = len(data)
        if tl < 16777216:
            #type for string is '0', so we don't need
            #to xor anything in
            handle.sendall(struct.pack("!I", tl))
        else:
            raise Exception("String data length exceeds protocol")
        handle.sendall(data)
    elif isinstance(data, dict):  # JSON currently only goes to 4 bytes
        # Some structured message, like what would be seen in http responses
        sdata = json.dumps(data, separators=(',', ':'))
        tl = len(sdata)
        if tl > 16777215:
            raise Exception("JSON data exceeds protocol limits")
        # xor in the type (0b1 << 24)
        tl |= 16777216
        handle.sendall(struct.pack("!I", tl))
        handle.sendall(sdata)


def recv(handle):
    tl = handle.recv(4)
    if len(tl) == 0:
        return None
    tl = struct.unpack("!I", tl)[0]
    if tl & 0b10000000000000000000000000000000:
        raise Exception("Protocol Violation, reserved bit set")
    # 4 byte tlv
    dlen = tl & 16777215  # grab lower 24 bits
    datatype = (tl & 2130706432) >> 24  # grab 7 bits from near beginning
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
