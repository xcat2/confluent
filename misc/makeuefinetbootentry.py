import argparse
import struct
import os
import sys

# This script will create a PXE or HTTP boot entry specific for a linux nic using
# convenience of the linux interface name. It can help produce precise network boot order
# configuration more easily if that is useful

# only tested with Lenovo system firmware on PCIe network adapters

parser = argparse.ArgumentParser(description='Generate an efivars boot entry file')
parser.add_argument('interface', help='Current linux interface name to boot from')
parser.add_argument('outfile', help='The file to write, e.g. /sys/firmware/efi/efivars/Boot0007-8be4df61-93ca-11d2-aa0d-00e098032b8c')
parser.add_argument('-u', help='The HTTP url to boot, "" for generic HTTP boot instead of PXE')
args = parser.parse_args()
with open('/sys/class/net/{0}/address'.format(sys.argv[1])) as macaddr:
    macaddr = macaddr.read()
    macaddr = macaddr.split(':')
    macaddr = [ int(x, 16) for x in macaddr ]
    macaddr = bytes(macaddr)

olddir = os.getcwd()
os.chdir('/sys/class/net/{0}'.format(sys.argv[1]))
devdir = os.readlink('/sys/class/net/{0}/device'.format(sys.argv[1]))
os.chdir(devdir)
pcipath = os.getcwd()
pcipath = pcipath.split('/')
os.chdir('/'.join(pcipath[:4]))
acpiid = os.readlink('firmware_node')
os.chdir(acpiid)
hid = '0A03' # do not adapt, always say pciroot, pcieroot doesn't work open('hid').read().replace('PNP', '')
hid = int(hid, 16) << 16 | 0x41d0
hid = struct.pack('<I', hid)
uid = open('uid').read()
uid = struct.pack('<I', int(uid, 16))
pcipath = pcipath[4:]
os.chdir(olddir)
url = args.u
if url is not None:
    url = url.encode('utf8')

with open(sys.argv[2], 'wb') as output:
    output.write(struct.pack('<I', 7)) # write out attributes, for now always 7
    output.write(struct.pack('<I', 1)) # write out attributes, for now always 1
    # 0x50 is smallest, acpi, mac, and ip devpaths, each pci path hop adds 6 bytes
    baselen = 0x50
    if url is not None: #well, we need more length for http boot
        baselen += len(url) + 4
    output.write(struct.pack('<H', baselen + (len(pcipath) * 6)))
    desc = sys.argv[1]
    if url is None:
        desc += '-pxe'
    else:
        desc += '-http'
    output.write(desc.encode('utf16')[2:])
    output.write(b'\x00\x00') # terminate the description
    # first we need pciroot, which is an acpi path, table 52, HID is PNP0A03
    output.write(b'\x02\x01\x0c\x00') # acpi devpath header
    output.write(hid) # ACPI hid, either PciRoot or PcieRoot
    output.write(uid) # ACPI uid of the pci root complex
    for pcihop in pcipath:
        pcihop = pcihop.rsplit(':', 1)[-1]
        output.write(b'\x01\x01\x06\x00')
        devnum, funnum = pcihop.split('.')
        devnum = int(devnum, 16)
        funnum = int(funnum, 16)
        output.write(struct.pack('BB', funnum, devnum))
    output.write(b'\x03\x0b\x25\x00')
    output.write(macaddr)
    output.write(b'\x00' * (32 - len(macaddr))) # pad out to the rest of the 32 bytes
    output.write(b'\x01') # type is ethernet, 1, per rfc 3232
    output.write(b'\x03\x0c\x1b\x00') # ipv4 header, table 71 from section 10.3.4.12
    output.write(b'\x00' * 23) # all zero for the data
    # if args.u, we need a Messaging device path, subtypee 24, uri, table 83
    if url is not None:
        output.write(b'\x03\x18')
        output.write(struct.pack('<H', 4 + len(url)))
        if url:
            output.write(url)
    output.write(b'\x7f\xff\x04\x00') # table 45, device path end structure

