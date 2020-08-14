# Copyright 2017 Lenovo
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

import argparse
import ctypes
import fcntl
from select import select
import struct
import sys
import time

class IpmiMsg(ctypes.Structure):
    _fields_ = [('netfn', ctypes.c_ubyte),
                ('cmd', ctypes.c_ubyte),
                ('data_len', ctypes.c_short),
                ('data', ctypes.POINTER(ctypes.c_ubyte))]


class IpmiSystemInterfaceAddr(ctypes.Structure):
    _fields_ = [('addr_type', ctypes.c_int),
                ('channel', ctypes.c_short),
                ('lun', ctypes.c_ubyte)]


class IpmiRecv(ctypes.Structure):
    _fields_ = [('recv_type', ctypes.c_int),
                ('addr', ctypes.POINTER(IpmiSystemInterfaceAddr)),
                ('addr_len', ctypes.c_uint),
                ('msgid', ctypes.c_long),
                ('msg', IpmiMsg)]


class IpmiReq(ctypes.Structure):
    _fields_ = [('addr', ctypes.POINTER(IpmiSystemInterfaceAddr)),
                ('addr_len', ctypes.c_uint),
                ('msgid', ctypes.c_long),
                ('msg', IpmiMsg)]


_IONONE = 0
_IOWRITE = 1
_IOREAD = 2
IPMICTL_SET_MY_ADDRESS_CMD = (
    _IOREAD << 30 | ctypes.sizeof(ctypes.c_uint) << 16
    | ord('i') << 8 | 17)  # from ipmi.h
IPMICTL_SEND_COMMAND = (
    _IOREAD << 30 | ctypes.sizeof(IpmiReq) << 16
    | ord('i') << 8 | 13)  # from ipmi.h
# next is really IPMICTL_RECEIVE_MSG_TRUNC, but will only use that
IPMICTL_RECV = (
    (_IOWRITE | _IOREAD) << 30 | ctypes.sizeof(IpmiRecv) << 16
    | ord('i') << 8 | 11)  # from ipmi.h
BMC_SLAVE_ADDR = ctypes.c_uint(0x20)
CURRCHAN = 0xf
ADDRTYPE = 0xc


class Session(object):
    def __init__(self, devnode='/dev/ipmi0'):
        """Create a local session inband

        :param: devnode: The path to the ipmi device
        """
        self.ipmidev = open(devnode, 'r+')
        fcntl.ioctl(self.ipmidev, IPMICTL_SET_MY_ADDRESS_CMD, BMC_SLAVE_ADDR)
        # the interface is initted, create some reusable memory for our session
        self.databuffer = ctypes.create_string_buffer(4096)
        self.req = IpmiReq()
        self.rsp = IpmiRecv()
        self.addr = IpmiSystemInterfaceAddr()
        self.req.msg.data = ctypes.cast(
            ctypes.addressof(self.databuffer),
            ctypes.POINTER(ctypes.c_ubyte))
        self.rsp.msg.data = self.req.msg.data
        self.userid = None
        self.password = None

    def await_reply(self):
        rd, _, _ = select((self.ipmidev,), (), (), 1)
        while not rd:
            rd, _, _ = select((self.ipmidev,), (), (), 1)

    def pause(self, seconds):
        time.sleep(seconds)

    @property
    def parsed_rsp(self):
        response = {'netfn': self.rsp.msg.netfn, 'command': self.rsp.msg.cmd,
                    'code': bytearray(self.databuffer.raw)[0],
                    'data': bytearray(
                        self.databuffer.raw[1:self.rsp.msg.data_len])}
        return response

    def raw_command(self,
                    netfn,
                    command,
                    data=(),
                    bridge_request=None,
                    retry=True,
                    delay_xmit=None,
                    timeout=None,
                    waitall=False, rslun=0):
        self.addr.channel = CURRCHAN
        self.addr.addr_type = ADDRTYPE
        self.addr.lun = rslun
        self.req.addr_len = ctypes.sizeof(IpmiSystemInterfaceAddr)
        self.req.addr = ctypes.pointer(self.addr)
        self.req.msg.netfn = netfn
        self.req.msg.cmd = command
        if data:
            data = memoryview(bytearray(data))
            try:
                self.databuffer[:len(data)] = data[:len(data)]
            except ValueError:
                self.databuffer[:len(data)] = data[:len(data)].tobytes()
        self.req.msg.data_len = len(data)
        fcntl.ioctl(self.ipmidev, IPMICTL_SEND_COMMAND, self.req)
        self.await_reply()
        self.rsp.msg.data_len = 4096
        self.rsp.addr = ctypes.pointer(self.addr)
        self.rsp.addr_len = ctypes.sizeof(IpmiSystemInterfaceAddr)
        fcntl.ioctl(self.ipmidev, IPMICTL_RECV, self.rsp)
        return self.parsed_rsp


def _is_tsm(model):
    return model in ('7y00', '7z01', '7y98', '7y99')

def set_port(s, port, vendor, model):
    oport = port
    if vendor not in ('IBM', 'Lenovo'):
        raise Exception('{0} not implemented'.format(vendor))
    if _is_tsm(model):
        set_port_tsm(s, port, model)
    else:
        set_port_xcc(s, port, model)


def set_port_tsm(s, port, model):
    oport = port
    sys.stdout.write('Setting TSM port to "{}"...'.format(oport))
    sys.stdout.flush()
    if port == 'ocp':
        s.raw_command(0x32, 0x71, b'\x00\x01\x00')
    elif port == 'dedicated':
        s.raw_command(0x32, 0x71, b'\x00\x00\x00')
    timer = 15
    while timer:
        time.sleep(1.0)
        sys.stdout.write('.')
        sys.stdout.flush()
    if port == 'ocp':
        s.raw_command(0x32, 0x71, b'\x00\x00\x03')
    elif port == 'dedicated':
        s.raw_command(0x32, 0x71, b'\x00\x01\x03')
    print('Complete')


def set_port_xcc(s, port, model):
    oport = port
    if port.lower() == 'dedicated':
        port = b'\x01'
    elif port.lower() in ('ml2', 'ocp'):
        port = b'\x02\x00'
    elif port.lower() == 'lom':
        if model == '7x58':
            port = b'\x00\x02'
        else:
            port = b'\x00\x00'
    else:
        port = port.split(' ')
        port = bytes(bytearray([int(x) for x in port]))
    currport = bytes(s.raw_command(0xc, 2, b'\x01\xc0\x00\x00')['data'][1:])
    if port == currport:
        sys.stdout.write('XCC port already set to "{}"\n'.format(oport))
        return
    sys.stdout.write('Setting XCC port to "{}"...'.format(oport))
    sys.stdout.flush()
    s.raw_command(0xc, 1, b'\x01\xc0' + port)
    tries = 60
    while currport != port and tries:
        tries -= 1
        time.sleep(0.5)
        sys.stdout.write('.')
        sys.stdout.flush()
        currport = bytes(s.raw_command(0xc, 2, b'\x01\xc0\x00\x00')['data'][1:])
    if not tries:
        raise Exception('Timeout attempting to set port')
    sys.stdout.write('Complete\n')


def set_vlan(s, vlan):
    ovlan = vlan
    if vlan == 'off':
        vlan = b'\x00\x00'
    else:
        vlan = int(vlan)
        if vlan:
            vlan = vlan | 32768
        vlan = struct.pack('<H', vlan)
    currvlan = bytes(s.raw_command(0xc, 2, b'\x01\x14\x00\x00')['data'][1:])
    if currvlan == vlan:
        sys.stdout.write('VLAN already configured to "{0}"\n'.format(ovlan))
        return False
    rsp = s.raw_command(0xc, 1, b'\x01\x14' + vlan)
    if rsp.get('code', 1) == 0:
        print('VLAN configured to "{}"'.format(ovlan))
    else:
        print('Error setting vlan: ' + repr(rsp))
    return


def main():
    a = argparse.ArgumentParser(description='Locally configure a BMC device')
    a.add_argument('-v', help='vlan id or off to disable vlan tagging')
    a.add_argument('-p', help='Which port to use (dedicated, lom, ocp, ml2)')
    args = a.parse_args()
    vendor = open('/sys/devices/virtual/dmi/id/sys_vendor').read()
    vendor = vendor.strip()
    try:
        model = open('/sys/devices/virtual/dmi/id/product_sku').read()
    except Exception:
        model = open('/sys/devices/virtual/dmi/id/product_name').read()
    if vendor in ('Lenovo', 'IBM'):
        if '[' in model and ']' in model:
            model = model.split('[')[1].split(']')[0]
        model = model[:4].lower()
    s = Session('/dev/ipmi0')
    if args.p is not None:
        set_port(s, args.p, vendor, model)
    if args.v is not None:
        set_vlan(s, args.v)


if __name__ == '__main__':
    main()
