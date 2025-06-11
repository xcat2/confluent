#!/usr/bin/python
import eventlet
import eventlet.green.select as select
import eventlet.green.subprocess as subprocess
from fnmatch import fnmatch
import glob
import logging
logging.getLogger('libarchive').addHandler(logging.NullHandler())
import libarchive
import hashlib
import os
import shutil
import sys
import time
import yaml
if __name__ == '__main__':
    path = os.path.dirname(os.path.realpath(__file__))
    path = os.path.realpath(os.path.join(path, '..'))
    if path.startswith('/opt'):
        sys.path.append(path)

import confluent.exceptions as exc
import confluent.messages as msg

COPY = 1
EXTRACT = 2
READFILES = set([
    '.disk/info',
    'media.1/products',
    'media.2/products',
    '.DISCINFO',
    '.discinfo',
    'zipl.prm',
    'sources/idwbinfo.txt',
])

HEADERSUMS = set([b'\x85\xeddW\x86\xc5\xbdhx\xbe\x81\x18X\x1e\xb4O\x14\x9d\x11\xb7C8\x9b\x97R\x0c-\xb8Ht\xcb\xb3'])
HASHPRINTS = {
    '69d5f1c5e4474d70b0fb5374bfcb29bf57ba828ff00a55237cd757e61ed71048': {'name': 'cumulus-broadcom-amd64-4.0.0', 'method': COPY},
}

from ctypes import byref, c_longlong, c_size_t, c_void_p

from libarchive.ffi import (
    write_disk_new, write_disk_set_options, write_free, write_header,
    read_data_block, write_data_block, write_finish_entry, ARCHIVE_EOF
)

def relax_umask():
    os.umask(0o22)


def makedirs(path, mode):
    try:
        os.makedirs(path, mode)
    except OSError as e:
        if e.errno != 17:
            raise

def symlink(src, targ):
    try:
        os.symlink(src, targ)
    except OSError as e:
        if e.errno != 17:
            raise


def update_boot(profilename):
    if profilename.startswith('/var/lib/confluent/public'):
        profiledir = profilename
    else:
        profiledir = '/var/lib/confluent/public/os/{0}'.format(profilename)
    profile = {}
    if profiledir.endswith('/'):
        profiledir = profiledir[:-1]
    profname = os.path.basename(profiledir)
    with open('{0}/profile.yaml'.format(profiledir)) as profileinfo:
        profile = yaml.safe_load(profileinfo)
    label = profile.get('label', profname)
    ostype = profile.get('ostype', 'linux')
    if ostype == 'linux':
        update_boot_linux(profiledir, profile, label)
    elif ostype == 'esxi':
        update_boot_esxi(profiledir, profile, label)

def update_boot_esxi(profiledir, profile, label):
    profname = os.path.basename(profiledir)
    kernelargs = profile.get('kernelargs', '')
    oum = os.umask(0o22)
    bootcfg = open('{0}/distribution/BOOT.CFG'.format(profiledir), 'r').read()
    bootcfg = bootcfg.split('\n')
    newbootcfg = ''
    efibootcfg = ''
    filesneeded = []
    localabel = label
    if 'installation of' not in localabel:
        localabel = 'Confluent installation of {}'.format(localabel)
    for cfgline in bootcfg:
        if cfgline.startswith('title='):
            newbootcfg += 'title={0}\n'.format(localabel)
            efibootcfg += 'title={0}\n'.format(localabel)
        elif cfgline.startswith('kernelopt='):
            newbootcfg += 'kernelopt={0}\n'.format(kernelargs)
            efibootcfg += 'kernelopt={0}\n'.format(kernelargs)
        elif cfgline.startswith('kernel='):
            kern = cfgline.split('=', 1)[1]
            kern = kern.replace('/', '')
            newbootcfg += 'kernel={0}\n'.format(kern)
            efibootcfg += cfgline + '\n'
            filesneeded.append(kern)
        elif cfgline.startswith('modules='):
            modlist = cfgline.split('=', 1)[1]
            mods = modlist.split(' --- ')
            efibootcfg += 'modules=' + ' --- '.join(mods) + ' --- /initramfs/addons.tgz --- /site.tgz\n'
            mods = [x.replace('/', '') for x in mods]
            filesneeded.extend(mods)
            newbootcfg += 'modules=' + ' --- '.join(mods) + ' --- initramfs/addons.tgz --- site.tgz\n'
        else:
            newbootcfg += cfgline + '\n'
            efibootcfg += cfgline + '\n'
    makedirs('{0}/boot/efi/boot/'.format(profiledir), 0o755)
    bcfgout = os.open('{0}/boot/efi/boot/boot.cfg'.format(profiledir), os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o644)
    bcfg = os.fdopen(bcfgout, 'w')
    try:
        bcfg.write(efibootcfg)
    finally:
        bcfg.close()
    bcfgout = os.open('{0}/boot/boot.cfg'.format(profiledir), os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o644)
    bcfg = os.fdopen(bcfgout, 'w')
    try:
        bcfg.write(newbootcfg)
    finally:
        bcfg.close()
    symlink('/var/lib/confluent/public/site/initramfs.tgz',
               '{0}/boot/site.tgz'.format(profiledir))
    for fn in filesneeded:
        if fn.startswith('/'):
            fn = fn[1:]
        sourcefile = '{0}/distribution/{1}'.format(profiledir, fn)
        if not os.path.exists(sourcefile):
            sourcefile = '{0}/distribution/{1}'.format(profiledir, fn.upper())
        symlink(sourcefile, '{0}/boot/{1}'.format(profiledir, fn))
    symlink('{0}/distribution/EFI/BOOT/BOOTX64.EFI'.format(profiledir), '{0}/boot/efi/boot/bootx64.efi'.format(profiledir))
    if os.path.exists('{0}/distribution/EFI/BOOT/CRYPTO64.EFI'.format(profiledir)):
        symlink('{0}/distribution/EFI/BOOT/CRYPTO64.EFI'.format(profiledir), '{0}/boot/efi/boot/crypto64.efi'.format(profiledir))
    ipout = os.open(profiledir + '/boot.ipxe', os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o644)
    ipxeout = os.fdopen(ipout, 'w')
    try:
        os.umask(oum)
        ipxeout.write('#!ipxe\n')
        pname = os.path.split(profiledir)[-1]
        ipxeout.write(
            'chain boot/efi/boot/bootx64.efi -c /confluent-public/os/{0}/boot/boot.cfg'.format(pname))
    finally:
        ipxeout.close()
    subprocess.check_call(
        ['/opt/confluent/bin/dir2img', '{0}/boot'.format(profiledir),
         '{0}/boot.img'.format(profiledir), profname], preexec_fn=relax_umask)


def find_glob(loc, fileglob):
    grubcfgs = []
    for cdir, _, fs in os.walk(loc):
        for f in fs:
            if fnmatch(f, fileglob):
                grubcfgs.append(os.path.join(cdir, f))
    return grubcfgs


def update_boot_linux(profiledir, profile, label):
    profname = os.path.basename(profiledir)
    kernelargs = profile.get('kernelargs', '')
    needefi = False
    for grubexe in glob.glob(profiledir + '/boot/efi/boot/grubx64.efi'):
        with open(grubexe, 'rb') as grubin:
            grubcontent = grubin.read()
            uaidx = grubcontent.find(b'User-Agent: GRUB 2.0')
            if uaidx > 0:
                grubcontent = grubcontent[uaidx:]
                cridx = grubcontent.find(b'\r')
                if cridx > 1:
                    grubcontent = grubcontent[:cridx]
                    grubver = grubcontent.split(b'~', 1)[0]
                    grubver = grubver.rsplit(b' ', 1)[-1]
                    grubver = grubver.split(b'.')
                    if len(grubver) > 1:
                        if int(grubver[0]) < 3 and int(grubver[1]) < 3:
                            needefi = True
    lincmd = 'linuxefi' if needefi else 'linux'
    initrdcmd = 'initrdefi' if needefi else 'initrd'
    grubcfg = "set timeout=5\nmenuentry '"
    grubcfg += label
    grubcfg += "' {\n    " + lincmd + " /kernel " + kernelargs + "\n"
    initrds = []
    for initramfs in glob.glob(profiledir + '/boot/initramfs/*.cpio'):
        initramfs = os.path.basename(initramfs)
        initrds.append(initramfs)
    for initramfs in os.listdir(profiledir + '/boot/initramfs'):
        if initramfs not in initrds:
            initrds.append(initramfs)
    grubcfg += "    " + initrdcmd + " "
    for initramfs in initrds:
        grubcfg += " /initramfs/{0}".format(initramfs)
    grubcfg += "\n}\n"
    # well need to honor grubprefix path if different
    grubcfgpath = find_glob(profiledir + '/boot', 'grub.cfg')
    if not grubcfgpath:
        grubcfgpath = [
                profiledir + '/boot/efi/boot/grub.cfg',
                profiledir + '/boot/boot/grub/grub.cfg'
                ]
    for grubcfgpth in grubcfgpath:
        os.makedirs(os.path.dirname(grubcfgpth), 0o755, exist_ok=True)
        with open(grubcfgpth, 'w') as grubout:
            grubout.write(grubcfg)
    ipxeargs = kernelargs
    for initramfs in initrds:
        ipxeargs += " initrd=" + initramfs
    oum = os.umask(0o22)
    ipout = os.open(profiledir + '/boot.ipxe', os.O_WRONLY|os.O_CREAT|os.O_TRUNC, 0o644)
    ipxeout = os.fdopen(ipout, 'w')
    try:
        os.umask(oum)
        ipxeout.write('#!ipxe\n')
        ipxeout.write('imgfetch boot/kernel ' + ipxeargs + '\n')
        for initramfs in initrds:
            ipxeout.write('imgfetch boot/initramfs/{0}\n'.format(initramfs))
        ipxeout.write('imgload kernel\nimgexec kernel\n')
    finally:
        ipxeout.close()
    subprocess.check_call(
        ['/opt/confluent/bin/dir2img', '{0}/boot'.format(profiledir),
         '{0}/boot.img'.format(profiledir), profname], preexec_fn=relax_umask)


def extract_entries(entries, flags=0, callback=None, totalsize=None, extractlist=None):
    """Extracts the given archive entries into the current directory.
    """
    buff, size, offset = c_void_p(), c_size_t(), c_longlong()
    buff_p, size_p, offset_p = byref(buff), byref(size), byref(offset)
    sizedone = 0
    printat = 0
    with libarchive.extract.new_archive_write_disk(flags) as write_p:
        for entry in entries:
            if str(entry).endswith('TRANS.TBL'):
                continue
            if extractlist and str(entry).lower() not in extractlist:
                continue
            write_header(write_p, entry._entry_p)
            read_p = entry._archive_p
            while 1:
                r = read_data_block(read_p, buff_p, size_p, offset_p)
                sizedone += size.value
                if callback and time.time() > printat:
                    callback({'progress': float(sizedone) / float(totalsize)})
                    printat = time.time() + 0.5
                if r == ARCHIVE_EOF:
                    break
                write_data_block(write_p, buff, size, offset)
            write_finish_entry(write_p)
            if os.path.isdir(str(entry)):
                # This directory must be world accessible for web server
                os.chmod(str(entry), 0o755)  # nosec
            else:
                os.chmod(str(entry), 0o644)
    if callback:
        callback({'progress': float(sizedone) / float(totalsize)})
    return float(sizedone) / float(totalsize)


def extract_file(archfile, flags=0, callback=lambda x: None, imginfo=(), extractlist=None):
    """Extracts an archive from a file into the current directory."""
    totalsize = 0
    for img in imginfo:
        if not imginfo[img]:
            continue
        totalsize += imginfo[img]
    dfd = os.dup(archfile.fileno())
    os.lseek(dfd, 0, 0)
    pctdone = 0
    try:
        with libarchive.fd_reader(dfd) as archive:
            pctdone = extract_entries(archive, flags, callback, totalsize,
                                      extractlist)
    finally:
        os.close(dfd)
    return pctdone


def check_rocky(isoinfo):
    ver = None
    arch = None
    cat = None
    for entry in isoinfo[0]:
        if 'rocky-release-8' in entry:
            ver = entry.split('-')[2]
            arch = entry.split('.')[-2]
            cat = 'el8'
            break
        if 'rocky-release-9' in entry:
            ver = entry.split('-')[2]
            arch = entry.split('.')[-2]
            cat = 'el9'
            break
        if 'rocky-release-10' in entry:
            ver = entry.split('-')[2]
            arch = entry.split('.')[-2]
            cat = 'el10'
            break
    else:
        return None
    if arch == 'noarch' and '.discinfo' in isoinfo[1]:
        prodinfo = isoinfo[1]['.discinfo']
        arch = prodinfo.split(b'\n')[2]
        if not isinstance(arch, str):
            arch = arch.decode('utf-8')
    return {'name': 'rocky-{0}-{1}'.format(ver, arch), 'method': EXTRACT, 'category': cat}

fedoracatmap = {
        '41': 'el10',
        '42': 'el10',
}
def check_fedora(isoinfo):
    if '.discinfo' not in isoinfo[1]:
        return None
    prodinfo = isoinfo[1]['.discinfo']
    prodlines = prodinfo.split(b'\n')
    if len(prodlines) < 3:
        return None
    prod = prodlines[1].split()[0]
    if prod != b'Fedora':
        return None
    arch = prodlines[2]
    ver = prodlines[1].split()[-1]
    if not isinstance(arch, str):
        arch = arch.decode('utf-8')
        ver = ver.decode('utf-8')
    if ver not in fedoracatmap:
        return None
    return {'name': 'fedora-{0}-{1}'.format(ver, arch), 'method': EXTRACT, 'category': fedoracatmap[ver]}

def check_alma(isoinfo):
    ver = None
    arch = None
    cat = None
    suffix = ""
    for entry in isoinfo[0]:
        if 'almalinux-release-8' in entry:
            ver = entry.split('-')[2]
            arch = entry.split('.')[-2]
            cat = 'el8'
            break
        elif 'almalinux-release-9' in entry:
            ver = entry.split('-')[2]
            arch = entry.split('.')[-2]
            cat = 'el9'
            break
        elif 'almalinux-release-10' in entry:
            ver = entry.split('-')[2]
            arch = entry.split('.')[-2]
            cat = 'el10'
            break
        elif 'almalinux-kitten-release-10' in entry:
            ver = entry.split('-')[3]
            arch = entry.split('.')[-2]
            cat = 'el10'
            suffix = '_kitten'
            break
    else:
        return None
    if arch == 'noarch' and '.discinfo' in isoinfo[1]:
        prodinfo = isoinfo[1]['.discinfo']
        arch = prodinfo.split(b'\n')[2]
        if not isinstance(arch, str):
            arch = arch.decode('utf-8')
    return {'name': 'alma{0}-{1}-{2}'.format(suffix, ver, arch), 'method': EXTRACT, 'category': cat}


def check_centos(isoinfo):
    ver = None
    arch = None
    cat = None
    isstream = ''
    for entry in isoinfo[0]:
        if 'centos-release-7' in entry:
            dotsplit = entry.split('.')
            arch = dotsplit[-2]
            ver = dotsplit[0].split('release-')[-1].replace('-', '.')
            cat = 'el7'
            break
        elif 'centos-release-8' in entry:
            ver = entry.split('-')[2]
            arch = entry.split('.')[-2]
            cat = 'el8'
            break
        elif 'centos-stream-release-8' in entry:
            ver = entry.split('-')[3]
            arch = entry.split('.')[-2]
            cat = 'el8'
            isstream = '_stream'
            break
        elif 'centos-stream-release-9' in entry:
            ver = entry.split('-')[3]
            arch = entry.split('.')[-2]
            cat = 'el9'
            isstream = '_stream'
            break
        elif 'centos-stream-release-10' in entry:
            ver = entry.split('-')[3]
            arch = entry.split('.')[-2]
            cat = 'el10'
            isstream = '_stream'
            break
        elif 'centos-linux-release-8' in entry:
            ver = entry.split('-')[3]
            arch = entry.split('.')[-2]
            cat = 'el8'
            break
    else:
        return None
    if arch == 'noarch' and '.discinfo' in isoinfo[1]:
        prodinfo = isoinfo[1]['.discinfo']
        arch = prodinfo.split(b'\n')[2]
        if not isinstance(arch, str):
            arch = arch.decode('utf-8')
    return {'name': 'centos{2}-{0}-{1}'.format(ver, arch, isstream), 'method': EXTRACT, 'category': cat}

def check_esxi(isoinfo):
    if '.DISCINFO' not in isoinfo[1]:
        return
    isesxi = False
    version = None
    for line in isoinfo[1]['.DISCINFO'].split(b'\n'):
        if b'ESXi' == line:
            isesxi = True
        if line.startswith(b'Version: '):
            _, version = line.split(b' ', 1)
            if not isinstance(version, str):
                version = version.decode('utf8')
    if isesxi and version:
        return {
            'name': 'esxi-{0}'.format(version),
            'method': EXTRACT,
            'category': 'esxi{0}'.format(version.split('.', 1)[0])
        }

def check_debian(isoinfo):
    if '.disk/info' not in isoinfo[1]:
        return None
    diskinfo = isoinfo[1]['.disk/info']
    diskbits = diskinfo.split(b' ')
    if diskbits[0] == b'Debian':
        if b'mini.iso' not in diskbits:
            raise Exception("Debian only supports the 'netboot mini.iso' type images")
        major = diskbits[2].decode()
        arch = diskbits[4].decode()
        buildtag = diskbits[-1].decode().strip() # 20230607+deb12u10
        minor = '0'
        if '+' in buildtag:
            _, variant = buildtag.split('+')
            variant = variant.replace('deb', '')
            if 'u' in variant:
                minor = variant.split('u')[1]
        version = '{0}.{1}'.format(major, minor)

        if arch != 'amd64':
            raise Exception("Unsupported debian architecture {}".format(arch))
        arch = 'x86_64'
        name = 'debian-{0}-{1}'.format(version, arch)
        return {
            'name': name,
            'method': EXTRACT,
            'category': 'debian',
        }


def check_ubuntu(isoinfo):
    if '.disk/info' not in isoinfo[1]:
        return None
    arch = None
    variant = None
    ver = None
    diskdefs = isoinfo[1]['.disk/info']
    for info in diskdefs.split(b'\n'):
        if not info:
            continue
        info = info.split(b' ')
        name = info[0].strip()
        ver = info[1].strip()
        arch = info[-2].strip()
        if name != b'Ubuntu-Server':
            return None
        if arch == b'amd64':
            arch = b'x86_64'
    if ver:
        if not isinstance(ver, str):
            ver = ver.decode('utf8')
        if not isinstance(arch, str):
            arch = arch.decode('utf8')
        major = '.'.join(ver.split('.', 2)[:2])
        if 'install/hwe-netboot/ubuntu-installer/amd64/linux' in isoinfo[0]:
            # debian-installer style amd64
            return {
                'name': 'ubuntu-{0}-{1}'.format(ver, arch),
                'method': EXTRACT,
                'category': 'ubuntu{0}'.format(major)}
        elif 'efi/boot/bootaa64.efi' in isoinfo[0]:
            exlist = ['casper/vmlinuz', 'casper/initrd',
                    'efi/boot/bootaa64.efi', 'efi/boot/grubaa64.efi'
                    ]
        else:
            exlist = ['casper/vmlinuz', 'casper/initrd',
                    'efi/boot/bootx64.efi', 'efi/boot/grubx64.efi'
                    ]
        return {'name': 'ubuntu-{0}-{1}'.format(ver, arch),
                'method': EXTRACT|COPY,
                'extractlist': exlist,
                'copyto': 'install.iso',
                'category': 'ubuntu{0}'.format(major)}


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
    major = ver.split('.', 2)[0]
    if hline[-1].startswith('15'):
        if hline[1] == 'openSUSE-Leap':
            distro = 'opensuse_leap'
        else:
            distro = 'sle'
        if hline[0] == '/' or 'boot' in isoinfo[0]:
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
        return {'name': '{0}-{1}-{2}'.format(distro, ver, arch),
                'method': EXTRACT, 'subname': disk,
                'category': 'suse{0}'.format(major)}
    return None


def _priv_check_oraclelinux(isoinfo):
    ver = None
    arch = None
    for entry in isoinfo[0]:
        if 'oraclelinux-release-' in entry and 'release-el7' not in entry:
            ver = entry.split('-')[2]
            arch = entry.split('.')[-2]
            break
    else:
        return None
    major = ver.split('.', 1)[0]
    return {'name': 'oraclelinux-{0}-{1}'.format(ver, arch), 'method': EXTRACT,
            'category': 'el{0}'.format(major)}


def fixup_coreos(targpath):
    # the efi boot image holds content that the init script would want
    # to mcopy, but the boot sector is malformed usually, so change it to 1
    # sector per track
    if os.path.exists(targpath + '/images/efiboot.img'):
        with open(targpath + '/images/efiboot.img', 'rb+') as bootimg:
            bootimg.seek(0x18)
            if bootimg.read != b'\x00\x00':
                bootimg.seek(0x18)
                bootimg.write(b'\x01')


def check_coreos(isoinfo):
    arch = 'x86_64'  # TODO: would check magic of vmlinuz to see which arch
    if 'zipl.prm' in isoinfo[1]:
        prodinfo = isoinfo[1]['zipl.prm']
        if not isinstance(prodinfo, str):
            prodinfo = prodinfo.decode('utf8')
        for inf in prodinfo.split():
            if inf.startswith('coreos.liveiso=rhcos-'):
                ver = inf.split('-')[1]
                return {'name': 'rhcos-{0}-{1}'.format(ver, arch),
                        'method': EXTRACT, 'category': 'coreos'}
            elif inf.startswith('coreos.liveiso=fedora-coreos-'):
                ver = inf.split('-')[2]
                return {'name': 'fedoracoreos-{0}-{1}'.format(ver, arch),
                        'method': EXTRACT, 'category': 'coreos'}



def check_rhel(isoinfo):
    ver = None
    arch = None
    isoracle = _priv_check_oraclelinux(isoinfo)
    if isoracle:
        return isoracle
    for entry in isoinfo[0]:
        if 'redhat-release-7' in entry:
            dotsplit = entry.split('.')
            arch = dotsplit[-2]
            ver = dotsplit[0].split('release-')[-1].replace('-', '.')
            break
        elif 'redhat-release-server-7' in entry:
            dotsplit = entry.split('.')
            arch = dotsplit[-2]
            ver = dotsplit[0].split('release-server-')[-1].replace('-', '.')
            if '.' not in ver:
                minor = dotsplit[1].split('-', 1)[0]
                ver = ver + '.' + minor
            break
        elif 'redhat-release-8' in entry:
            ver = entry.split('-')[2]
            arch = entry.split('.')[-2]
            break
        elif 'redhat-release-9' in entry:
            ver = entry.split('-')[2]
            arch = entry.split('.')[-2]
            break
        elif 'redhat-release-10' in entry:
            ver = entry.split('-')[2]
            arch = entry.split('.')[-2]
            break
    else:
        if '.discinfo' in isoinfo[1]:
            prodinfo = isoinfo[1]['.discinfo']
            if not isinstance(prodinfo, str):
                prodinfo = prodinfo.decode('utf8')
                prodinfo = prodinfo.split('\n')
                if len(prodinfo) < 3:
                    return None
                arch = prodinfo[2]
                prodinfo = prodinfo[1].split(' ')
                if len(prodinfo) < 2 or prodinfo[0] != 'RHVH':
                    return None
                major = prodinfo[1].split('.')[0]
                cat = 'rhvh{0}'.format(major)
                return {'name': 'rhvh-{0}-{1}'.format(prodinfo[1], arch),
                        'method': EXTRACT, 'category': cat}
        return None
    major = ver.split('.', 1)[0]
    return {'name': 'rhel-{0}-{1}'.format(ver, arch), 'method': EXTRACT, 'category': 'el{0}'.format(major)}


def scan_iso(archive):
    filesizes = {}
    filecontents = {}
    dfd = os.dup(archive.fileno())
    os.lseek(dfd, 0, 0)
    try:
        with libarchive.fd_reader(dfd) as reader:
            for ent in reader:
                if str(ent).endswith('TRANS.TBL'):
                    continue
                eventlet.sleep(0)
                filesizes[str(ent)] = ent.size
                if str(ent) in READFILES:
                    filecontents[str(ent)] = b''
                    for block in ent.get_blocks():
                        filecontents[str(ent)] += bytes(block)
    finally:
        os.close(dfd)
    return filesizes, filecontents


def fingerprint(archive):
    archive.seek(0)
    header = archive.read(32768)
    archive.seek(32769)
    if archive.read(6) == b'CD001\x01':
        # ISO image
        isoinfo = scan_iso(archive)
        name = None
        for fun in globals():
            if fun.startswith('check_'):
                name = globals()[fun](isoinfo)
                if name:
                    return name, isoinfo[0], fun.replace('check_', '')
        return None
    else:
        sum = hashlib.sha256(header)
        if sum.digest() in HEADERSUMS:
            archive.seek(32768)
            chunk = archive.read(32768)
            while chunk:
                sum.update(chunk)
                chunk = archive.read(32768)
            imginfo = HASHPRINTS.get(sum.hexdigest(), None)
            if imginfo:
                return imginfo, None, None


def import_image(filename, callback, backend=False, mfd=None, custtargpath=None, custdistpath=None, custname=''):
    if mfd:
        archive = os.fdopen(int(mfd), 'rb')
    else:
        archive = open(filename, 'rb')
    identity = fingerprint(archive)
    if not identity:
        return -1
    identity, imginfo, funname = identity
    distpath = custdistpath
    if not distpath:
        targpath = identity['name']
        distpath = '/var/lib/confluent/distributions/' + targpath
    if not custtargpath:
        if identity.get('subname', None):
            targpath += '/' + identity['subname']
        targpath = '/var/lib/confluent/distributions/' + targpath
    else:
        targpath = custtargpath
    try:
        os.makedirs(targpath, 0o755)
    except Exception as e:
        sys.stdout.write('ERROR:{0}\r'.format(str(e)))
    filename = os.path.abspath(filename)
    identity['importedfile'] = filename
    os.chdir(targpath)
    if not backend:
        print('Importing OS to ' + targpath + ':')
    callback({'progress': 0.0})
    pct = 0.0
    if EXTRACT & identity['method']:
        pct = extract_file(archive, callback=callback, imginfo=imginfo,
                           extractlist=identity.get('extractlist', None))
    if COPY & identity['method']:
        basename = identity.get('copyto', os.path.basename(filename))
        targiso = os.path.join(targpath, basename)
        archive.seek(0, 2)
        totalsz = archive.tell()
        currsz = 0
        modpct = 1.0 - pct
        archive.seek(0, 0)
        printat = 0
        with open(targiso, 'wb') as targ:
            buf = archive.read(32768)
            while buf:
                currsz += len(buf)
                pgress = pct + ((float(currsz) / float(totalsz)) * modpct)
                if time.time() > printat:
                    callback({'progress': pgress})
                    printat = time.time() + 0.5
                targ.write(buf)
                buf = archive.read(32768)
    with open(targpath + '/distinfo.yaml', 'w') as distinfo:
        distinfo.write(yaml.dump(identity, default_flow_style=False))
    if 'subname' in identity:
        del identity['subname']
    with open(distpath + '/distinfo.yaml', 'w') as distinfo:
        distinfo.write(yaml.dump(identity, default_flow_style=False))
    if 'fixup_{0}'.format(funname) in globals():
        globals()['fixup_{0}'.format(funname)](targpath)
    callback({'progress': 1.0})
    sys.stdout.write('\n')

def printit(info):
    sys.stdout.write('     \r{:.2f}%'.format(100 * info['progress']))
    sys.stdout.flush()


def list_distros():
    try:
        return sorted(os.listdir('/var/lib/confluent/distributions'))
    except FileNotFoundError:
        return []

def list_profiles():
    try:
        return sorted(os.listdir('/var/lib/confluent/public/os/'))
    except FileNotFoundError:
        return []

def get_profile_label(profile):
    with open('/var/lib/confluent/public/os/{0}/profile.yaml') as metadata:
        prof = yaml.safe_load(metadata)
    return prof.get('label', profile)

importing = {}


class ManifestMissing(Exception):
    pass

def copy_file(src, dst):
    newdir = os.path.dirname(dst)
    makedirs(newdir, 0o755)
    shutil.copy2(src, dst)

def get_hash(fname):
    currhash = hashlib.sha512()
    with open(fname, 'rb') as currf:
        currd = currf.read(2048)
        while currd:
            currhash.update(currd)
            currd = currf.read(2048)
    return currhash.hexdigest()


def rebase_profile(dirname):
    if dirname.startswith('/var/lib/confluent/public'):
        profiledir = dirname
    else:
        profiledir = '/var/lib/confluent/public/os/{0}'.format(dirname)
    currhashes = get_hashes(profiledir)
    festfile = os.path.join(profiledir, 'manifest.yaml')
    try:
        with open(festfile, 'r') as festfile:
            manifest = yaml.safe_load(festfile)
    except IOError:
        raise ManifestMissing()
    distdir = manifest['distdir']
    newdisthashes = get_hashes(distdir)
    olddisthashes = manifest['disthashes']
    customized = []
    newmanifest = []
    updated = []
    for updatecandidate in newdisthashes:
        newfilename = os.path.join(profiledir, updatecandidate)
        distfilename = os.path.join(distdir, updatecandidate)
        newdisthash = newdisthashes[updatecandidate]
        currhash = currhashes.get(updatecandidate, None)
        olddisthash = olddisthashes.get(updatecandidate, None)
        if not currhash:  # file does not exist yet
            copy_file(distfilename, newfilename)
            newmanifest.append(updatecandidate)
            updated.append(updatecandidate)
        elif currhash == newdisthash:
            newmanifest.append(updatecandidate)
        elif currhash != olddisthash:
            customized.append(updatecandidate)
        else:
            copy_file(distfilename, newfilename)
            updated.append(updatecandidate)
            newmanifest.append(updatecandidate)
    for nf in newmanifest:
        nfname = os.path.join(profiledir, nf)
        currhash = get_hash(nfname)
        manifest['disthashes'][nf] = currhash
    with open('{0}/manifest.yaml'.format(profiledir), 'w') as yout:
            yout.write('# This manifest enables rebase to know original source of profile data and if any customizations have been done\n')
            yout.write(yaml.dump(manifest, default_flow_style=False))
    return updated, customized

    # if currhash == disthash:
    #      no update required, update manifest
    # elif currhash != olddisthash:
    #      customization detected, skip
    # else
    #      update required, manifest update



def get_hashes(dirname):
    hashmap = {}
    for dname, _, fnames in os.walk(dirname):
        for fname in fnames:
            if fname == 'profile.yaml':
                continue
            fullname = os.path.join(dname, fname)
            currhash = hashlib.sha512()
            subname = fullname.replace(dirname + '/', '')
            if os.path.isfile(fullname):
                hashmap[subname] = get_hash(fullname)
    return hashmap


def generate_stock_profiles(defprofile, distpath, targpath, osname,
                            profilelist, customname):
    osd, osversion, arch = osname.split('-')
    bootupdates = []
    for prof in os.listdir('{0}/profiles'.format(defprofile)):
        srcname = '{0}/profiles/{1}'.format(defprofile, prof)
        if customname:
            profname = '{0}-{1}'.format(customname, prof)
        else:
            profname = '{0}-{1}'.format(osname, prof)
        dirname = '/var/lib/confluent/public/os/{0}'.format(profname)
        if os.path.exists(dirname):
            continue
        oumask = os.umask(0o22)
        shutil.copytree(srcname, dirname)
        hmap = get_hashes(dirname)
        profdata = None
        try:
            os.makedirs('{0}/boot/initramfs'.format(dirname), 0o755)
        except OSError as e:
            if e.errno != 17:
                raise
        finally:
            os.umask(oumask)
        with open('{0}/profile.yaml'.format(dirname)) as yin:
            profdata = yin.read()
            profdata = profdata.replace('%%DISTRO%%', osd)
            profdata = profdata.replace('%%VERSION%%', osversion)
            profdata = profdata.replace('%%ARCH%%', arch)
            profdata = profdata.replace('%%PROFILE%%', profname)
        if profdata:
            with open('{0}/profile.yaml'.format(dirname), 'w') as yout:
                yout.write(profdata)
        with open('{0}/manifest.yaml'.format(dirname), 'w') as yout:
            yout.write('# This manifest enables rebase to know original source of profile data and if any customizations have been done\n')
            manifestdata = {'distdir': srcname, 'disthashes': hmap}
            yout.write(yaml.dump(manifestdata, default_flow_style=False))
        initrds = ['{0}/initramfs/{1}'.format(defprofile, initrd) for initrd in os.listdir('{0}/initramfs'.format(defprofile))]
        if os.path.exists('{0}/initramfs/{1}'.format(defprofile, arch)):
            initrds.extend(['{0}/initramfs/{1}/{2}'.format(defprofile, arch, initrd) for initrd in os.listdir('{0}/initramfs/{1}'.format(defprofile, arch))])
        for fullpath in initrds:
            initrd = os.path.basename(fullpath)
            if os.path.isdir(fullpath):
                continue
            if os.path.exists('{0}/boot/initramfs/{1}'.format(dirname, initrd)):
                os.remove('{0}/boot/initramfs/{1}'.format(dirname, initrd))
            os.symlink(fullpath,
                       '{0}/boot/initramfs/{1}'.format(dirname, initrd))
        os.symlink(
            '/var/lib/confluent/public/site/initramfs.cpio',
            '{0}/boot/initramfs/site.cpio'.format(dirname))
        os.symlink(distpath, '{0}/distribution'.format(dirname))
        subprocess.check_call(
            ['sh', '{0}/initprofile.sh'.format(dirname),
             targpath, dirname])
        bootupdates.append(eventlet.spawn(update_boot, dirname))
        profilelist.append(profname)
    for upd in bootupdates:
        upd.wait()


class MediaImporter(object):

    def __init__(self, media, cfm=None, customname=None, checkonly=False):
        self.worker = None
        if not os.path.exists('/var/lib/confluent/public'):
            raise Exception('`osdeploy initialize` must be executed before importing any media')
        self.profiles = []
        self.errors = []
        medfile = None
        self.medfile = None
        if cfm and media in cfm.clientfiles:
            self.medfile = cfm.clientfiles[media]
            medfile = self.medfile
        else:
            medfile = open(media, 'rb')
        try:
            identity = fingerprint(medfile)
        finally:
            if not self.medfile:
                medfile.close()
        if not identity:
            raise exc.InvalidArgumentException('Unsupported Media')
        self.percent = 0.0
        identity, _, _ = identity
        self.phase = 'copying'
        if not identity:
            raise Exception('Unrecognized OS Media')
        self.customname = customname if customname else ''
        if customname:
            importkey = customname
        elif 'subname' in identity:
            importkey = '{0}-{1}'.format(identity['name'], identity['subname'])
        else:
            importkey = identity['name']
        if importkey in importing and not checkonly:
            raise Exception('Media import already in progress for this media')
        self.importkey = importkey
        self.osname = identity['name']
        self.oscategory = identity.get('category', None)
        if customname:
            targpath = customname
        else:
            targpath = identity['name']
        self.distpath = '/var/lib/confluent/distributions/' + targpath
        if identity.get('subname', None):  # subname is to indicate disk number in a media set
            targpath += '/' + identity['subname']
        self.targpath = '/var/lib/confluent/distributions/' + targpath
        if os.path.exists(self.targpath):
            errstr = '{0} already exists'.format(self.targpath)
            if checkonly:
                self.errors = [errstr]
            else:
                raise Exception(errstr)
        if checkonly:
            return
        importing[importkey] = self
        self.filename = os.path.abspath(media)
        self.error = ''
        self.importer = eventlet.spawn(self.importmedia)

    def stop(self):
        if self.worker and self.worker.poll() is None:
            self.worker.kill()

    @property
    def progress(self):
        return {'phase': self.phase, 'progress': self.percent, 'profiles': self.profiles, 'error': self.error}

    def importmedia(self):
        if self.medfile:
            os.environ['CONFLUENT_MEDIAFD'] = '{0}'.format(self.medfile.fileno())
        with open(os.devnull, 'w') as devnull:
            self.worker = subprocess.Popen(
                [sys.executable, __file__, self.filename, '-b', self.targpath, self.distpath, self.customname],
                stdin=devnull, stdout=subprocess.PIPE, close_fds=False)
        wkr = self.worker
        currline = b''
        while wkr.poll() is None:
            currline += wkr.stdout.read(1)
            if b'\r' in currline:
                if b'%' in currline:
                    val = currline.split(b'%')[0].strip()
                    if val:
                        self.percent = float(val)
                elif b'ERROR:' in currline:
                    self.error = currline.replace(b'ERROR:', b'')
                    if not isinstance(self.error, str):
                        self.error = self.error.decode('utf8')
                    self.phase = 'error'
                    self.percent = 100.0
                    return
                currline = b''
        a = wkr.stdout.read(1)
        while a:
            currline += a
            if b'\r' in currline:
                if b'%' in currline:
                    val = currline.split(b'%')[0].strip()
                    if val:
                        self.percent = float(val)
                elif b'ERROR:' in currline:
                    self.error = currline.replace(b'ERROR:', b'')
                    if not isinstance(self.error, str):
                        self.error = self.error.decode('utf8')
                    self.phase = 'error'
                    return
            currline = b''
            a = wkr.stdout.read(1)
        if self.oscategory:
            defprofile = '/opt/confluent/lib/osdeploy/{0}'.format(
                self.oscategory)
            try:
                generate_stock_profiles(defprofile, self.distpath, self.targpath,
                                        self.osname, self.profiles, self.customname)
            except Exception as e:
                self.phase = 'error'
                self.error = str(e)
                raise
        self.phase = 'complete'
        self.percent = 100.0


def list_importing():
    return [msg.ChildCollection(x) for x in importing]


def remove_importing(importkey):
    importing[importkey].stop()
    del importing[importkey]
    yield msg.DeletedResource('deployment/importing/{0}'.format(importkey))


def get_importing_status(importkey):
    yield msg.KeyValueData(importing[importkey].progress)


if __name__ == '__main__':
    os.umask(0o022)
    if len(sys.argv) > 2:
        mfd = os.environ.get('CONFLUENT_MEDIAFD', None)
        sys.exit(import_image(sys.argv[1], callback=printit, backend=True, mfd=mfd, custtargpath=sys.argv[3], custdistpath=sys.argv[4], custname=sys.argv[5]))
    else:
        sys.exit(import_image(sys.argv[1], callback=printit))

