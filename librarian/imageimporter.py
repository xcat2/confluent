import logging
logging.getLogger('libarchive').addHandler(logging.NullHandler())
import libarchive
import hashlib
import sys

READFILES = set([
    'media.1/products',
    'media.2/products',
    '.discinfo',
])

HEADERSUMS = set([b'\x85\xeddW\x86\xc5\xbdhx\xbe\x81\x18X\x1e\xb4O\x14\x9d\x11\xb7C8\x9b\x97R\x0c-\xb8Ht\xcb\xb3'])
HASHPRINTS = {
    '69d5f1c5e4474d70b0fb5374bfcb29bf57ba828ff00a55237cd757e61ed71048': ('cumulus-broadcom-amd64-4.0.0', None),
}

def check_centos(isoinfo):
    ver = None
    arch = None
    for entry in isoinfo[0]:
        if 'centos-release-7' in entry:
            dotsplit = entry.split('.')
            arch = dotsplit[-2]
            ver = dotsplit[0].split('release-')[-1].replace('-', '.')
            break
        elif 'centos-release-8' in entry:
            ver = entry.split('-')[2]
            arch = entry.split('.')[-2]
            break
    else:
        return None
    return ('centos-{0}-{1}'.format(ver, arch), None)


def check_sles(isoinfo):
    ver = None
    arch = 'x86_64'
    disk = None
    distro = ''
    if 'media.1/products' in isoinfo[1]:
        medianame = 'media.1/products'
    elif 'media.2/products' in isoinfo[1]:
        medianame = 'media.2/products'
    else:
        return None
    prodinfo = isoinfo[1][medianame]
    if not isinstance(prodinfo, str):
        prodinfo = prodinfo.decode('utf8')
    prodinfo = prodinfo.split('\n')
    hline = prodinfo[0].split(' ')
    ver = hline[-1].split('-')[0]
    if hline[-1].startswith('15'):
        distro = 'sle'
        if hline[0] == '/':
            disk = '1'
        elif hline[0].startswith('/Module'):
            disk = '2'
    elif hline[-1].startswith('12'):
        if 'SLES' in hline[1]:
            distro = 'sles'
        if '.1' in medianame:
            disk = '1'
        elif '.2' in medianame:
            disk = '2'
    if disk and distro:
        return ('{0}-{1}-{2}'.format(distro, ver, arch), disk)
    return None


def check_rhel(isoinfo):
    ver = None
    arch = None
    for entry in isoinfo[0]:
        if 'redhat-release-7' in entry:
            dotsplit = entry.split('.')
            arch = dotsplit[-2]
            ver = dotsplit[0].split('release-')[-1].replace('-', '.')
            break
        elif 'redhat-release-8' in entry:
            ver = entry.split('-')[2]
            arch = entry.split('.')[-2]
            break
    else:
        return None
    return ('rhel-{0}-{1}'.format(ver, arch), None)

def scan_iso(filename):
    filelist = []
    filecontents = {}
    with libarchive.file_reader(filename) as reader:
        for ent in reader:
            filelist.append(str(ent))
            if str(ent) in READFILES:
                filecontents[str(ent)] = b''
                for block in ent.get_blocks():
                    filecontents[str(ent)] += bytes(block)
    return filelist, filecontents

def fingerprint(filename):
    with open(sys.argv[1]) as archive:
        header = archive.read(32768)
        archive.seek(32769)
        if archive.read(6) == 'CD001\x01':
            # ISO image
            isoinfo = scan_iso(filename)
            name = None
            for fun in globals():
                if fun.startswith('check_'):
                    name = globals()[fun](isoinfo)
                    if name:
                        return name
            for file in isoinfo[0]:
                print(file)
            return None
        else:
            sum = hashlib.sha256(header)
            if sum.digest() in HEADERSUMS:
                archive.seek(32768)
                chunk = archive.read(32768)
                while chunk:
                    sum.update(chunk)
                    chunk = archive.read(32768)
                return HASHPRINTS.get(sum.hexdigest(), None)


if __name__ == '__main__':
    print(repr(fingerprint(sys.argv[1])))