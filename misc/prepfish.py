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
import json
from select import select
import glob
import hashlib
import socket
import struct
import os
import subprocess
import sys
import time
import ssl
import socket

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

def get_nicname_from_dmi():
    for fi in glob.glob('/sys/firmware/dmi/entries/42-*/raw'):
        dmit = memoryview(open(fi, 'rb').read())
        if dmit[0] != 42:
            continue
        if dmit[1] < 0xb:
            continue
        if dmit[4] != 0x40: # only supporting network host interface
            continue
        ifdatalen = dmit[5]
        ifdata = dmit[6:6+ifdatalen]
        if ifdata[0] != 2:
            continue
        idvend, idprod = struct.unpack('<HH', ifdata[1:5])
        for nici in glob.glob('/sys/class/net/*'):
            nicname = os.path.basename(nici)
            try:
                nicu = subprocess.check_output(['udevadm', 'info', nici], stderr=subprocess.DEVNULL)
            except Exception:
                raise
                continue
            nicu = nicu.decode()
            if f'ID_VENDOR_ID={idvend:04x}' in nicu and f'ID_MODEL_ID={idprod:04x}' in nicu:
                return nicname
    return None

def scan_nicname(nicname):
    idx = int(open('/sys/class/net/{}/ifindex'.format(nicname)).read())
    return scan_nic(idx)

def scan_nic(nicidx):
    srvs = {}
    s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    s6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    s6.bind(('::', 0))
    msg = b'M-SEARCH * HTTP/1.1\r\nHOST: [ff02::c]:1900\r\nMAN: "ssdp:discover"\r\nST: urn:dmtf-org:service:redfish-rest:1\r\nMX: 3\r\n\r\n'
    s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, nicidx)
    x = [False,]
    tries=5
    while not x[0] and tries:
        try:
            s6.sendto(msg, ('ff02::c', 1900))
        except Exception:
            pass
        x = select((s6,), (), (), 3.0)
        tries -= 1
    if not x[0]:
        raise Exception("Unable to find XCC via SSDP on {}".format(nicidx))
    (rsp, peer) = s6.recvfrom(9000)
    if '%' in peer[0]:
        return peer[0]
    else:
        return '{}%{}'.format(peer[0], nicidx)


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

class Verifier(object):
    def __init__(self, fprint):
        self._fprint = fprint

    def validate(self, certificate):
        return hashlib.sha256(certificate).digest() == self._fprint


def dotwait():
    sys.stderr.write('.')
    sys.stderr.flush()
    time.sleep(0.5)

def disable_host_interface():
    s = Session('/dev/ipmi0')
    rsp = s.raw_command(netfn=0xc, command=1, data=(1, 0xc1, 0))

def get_redfish_creds():
    os.makedirs('/run/redfish', exist_ok=True, mode=0o700)
    try:
        with open('/run/redfish/credentials', 'rb') as credin:
            cred = credin.read()
    except FileNotFoundError:
        s = Session('/dev/ipmi0')
        rsp = s.raw_command(netfn=0x2c, command=2, data=(0x52, 0xa5))
        cred = bytes(rsp['data'])
        with open('/run/redfish/credentials', 'wb') as credout:
            credout.write(cred)
    if cred[0] == 0x52:
        cred = cred[1:]
        creds = cred.split(b'\x00')[:2]
    return creds


def get_redfish_fingerprint():
    os.makedirs('/run/redfish', exist_ok=True, mode=0o700)
    try:
        with open('/run/redfish/fingerprint', 'rb') as certin:
            fprint = certin.read()
    except FileNotFoundError:
        s = Session('/dev/ipmi0')
        rsp = s.raw_command(0x2c, 1, data=(0x52, 1))
        if rsp['data'][:2] == b'\x52\x01':
            fprint = rsp['data'][2:]
        with open('/run/redfish/fingerprint', 'wb') as printout:
            printout.write(fprint)
    return fprint


def enable_host_interface():
    s = Session('/dev/ipmi0')
    rsp = s.raw_command(netfn=0xc, command=2, data=(1, 0xc1, 0, 0))
    usbenabled = rsp['data'][1] == 1
    disableusb = not usbenabled
    if not usbenabled:
        s.raw_command(netfn=0xc, command=1, data=(1, 0xc1, 1))
        sys.stderr.write("Enabling USB Interface")
    rsp = s.raw_command(netfn=0xc, command=2, data=(1, 0xc1, 0, 0))
    usbenabled = rsp['data'][1] == 1
    while not usbenabled:
        dotwait()
        rsp = s.raw_command(netfn=0xc, command=2, data=(1, 0xc1, 0, 0))
        usbenabled = rsp['data'][1] == 1
    usbnic = get_nicname_from_dmi()
    while not usbnic:
        dotwait()
        usbnic = get_nicname_from_dmi()
    bmctarg = scan_nicname(usbnic)
    while not bmctarg:
        dotwait()
        bmctarg = scan_nicname(usbnic)
    sys.stderr.write("USB NIC Established\n")
    sys.stderr.flush()
    return bmctarg

def store_redfish_cert(bmc):
    fprint = get_redfish_fingerprint()
    verifier = Verifier(fprint)
    peercert = None
    with socket.create_connection((bmc, 443)) as plainsock:
        finsock = ssl.wrap_socket(plainsock, cert_reqs=ssl.CERT_NONE)  # to allow fprint based cert
        peercert = finsock.getpeercert(binary_form=True)
        if not verifier.validate(peercert):
            raise Exception("Mismatched certificate")
    if peercert:
        with open('/run/redfish/cert.der', 'wb') as certout:
            certout.write(peercert)

def main():
    get_redfish_fingerprint()
    bmcuser, bmcpass = get_redfish_creds()
    bmc = enable_host_interface()
    store_redfish_cert(bmc)
    print('Redfish user: {}'.format(bmcuser.decode()))
    print('Redfish password: {}'.format(bmcpass.decode()))
    print('Redfish host: https://[{}]/'.format(bmc))


if __name__ == '__main__':
    main()
