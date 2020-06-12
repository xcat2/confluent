#!/usr/bin/python
import confluent.messages as msg
import eventlet
import eventlet.green.select as select
import eventlet.green.subprocess as subprocess
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

COPY = 1
EXTRACT = 2
READFILES = set([
    'README.diskdefines',
    'media.1/products',
    'media.2/products',
    '.DISCINFO',
    '.discinfo',
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

def update_boot(profiledir):
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
    kernelargs = profile.get('kernelargs', '')
    oum = os.umask(0o22)
    bootcfg = open('{0}/distribution/BOOT.CFG'.format(profiledir), 'r').read()
    bootcfg = bootcfg.split('\n')
    newbootcfg = ''
    filesneeded = []
    for cfgline in bootcfg:
        if cfgline.startswith('title='):
            newbootcfg += 'title={0}\n'.format(label)
        elif cfgline.startswith('kernelopt='):
            newbootcfg += 'kernelopt={0}\n'.format(kernelargs)
        elif cfgline.startswith('kernel='):
            newbootcfg += cfgline + '\n'
            kern = cfgline.split('=', 1)[1]
            filesneeded.append(kern)
        elif cfgline.startswith('modules='):
            modlist = cfgline.split('=', 1)[1]
            mods = modlist.split(' --- ')
            mods = [x.replace('/', '') for x in mods]
            filesneeded.extend(mods)

            newbootcfg += 'modules= + ' --- '.join(mods) + ' --- initramfs/addons.tgz --- site.tgz\n'
        else:
            newbootcfg += cfgline + '\n'
    os.makedirs('{0}/boot/efi/boot/'.format(profiledir), 0o755)
    bcfgout = os.open('{0}/boot/efi/boot/boot.cfg'.format(profiledir), os.O_WRONLY|os.O_CREAT, 0o644)
    bcfg = os.fdopen(bcfgout, 'w')
    try:
        bcfg.write(newbootcfg)
    finally:
        bcfg.close()
    os.symlink('/var/lib/confluent/public/site/initramfs.tgz',
               '{0}/boot/site.tgz'.format(profiledir))
    os.symlink('{0}/boot/efi/boot/boot.cfg'.format(profiledir), '{0}/boot/boot.cfg'.format(profiledir))
    for fn in filesneeded:
        if fn.startswith('/'):
            fn = fn[1:]
        sourcefile = '{0}/distribution/{1}'.format(profiledir, fn)
        if not os.path.exists(sourcefile):
            sourcefile = '{0}/distribution/{1}'.format(profiledir, fn.upper())
        os.symlink(sourcefile, '{0}/boot/{1}'.format(profiledir, fn))
    os.symlink('{0}/distribution/EFI/BOOT/BOOTX64.EFI'.format(profiledir), '{0}/boot/efi/boot/bootx64.efi'.format(profiledir))
    ipout = os.open(profiledir + '/boot.ipxe', os.O_WRONLY|os.O_CREAT, 0o644)
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
         '{0}/boot.img'.format(profiledir)], preexec_fn=relax_umask)


def update_boot_linux(profiledir, profile, label):
    kernelargs = profile.get('kernelargs', '')
    grubcfg = "set timeout=5\nmenuentry '"
    grubcfg += label
    grubcfg += "' {\n    linuxefi /kernel " + kernelargs + "\n"
    initrds = []
    for initramfs in glob.glob(profiledir + '/boot/initramfs/*.cpio'):
        initramfs = os.path.basename(initramfs)
        initrds.append(initramfs)
    for initramfs in os.listdir(profiledir + '/boot/initramfs'):
        if initramfs not in initrds:
            initrds.append(initramfs)
    grubcfg += "    initrdefi "
    for initramfs in initrds:
        grubcfg += " /initramfs/{0}".format(initramfs)
    grubcfg += "\n}\n"
    with open(profiledir + '/boot/efi/boot/grub.cfg', 'w') as grubout:
        grubout.write(grubcfg)
    ipxeargs = kernelargs
    for initramfs in initrds:
        ipxeargs += " initrd=" + initramfs
    oum = os.umask(0o22)
    ipout = os.open(profiledir + '/boot.ipxe', os.O_WRONLY|os.O_CREAT, 0o644)
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
         '{0}/boot.img'.format(profiledir)], preexec_fn=relax_umask)


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
            if extractlist and str(entry) not in extractlist:
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
    if callback:
        callback({'progress': float(sizedone) / float(totalsize)})


def extract_file(filepath, flags=0, callback=lambda x: None, imginfo=(), extractlist=None):
    """Extracts an archive from a file into the current directory."""
    totalsize = 0
    for img in imginfo:
        if not imginfo[img]:
            continue
        totalsize += imginfo[img]
    with libarchive.file_reader(filepath) as archive:
        extract_entries(archive, flags, callback, totalsize, extractlist)


def check_centos(isoinfo):
    ver = None
    arch = None
    cat = None
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
    else:
        return None
    return {'name': 'centos-{0}-{1}'.format(ver, arch), 'method': EXTRACT, 'category': cat}

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

def check_ubuntu(isoinfo):
    if 'README.diskdefines' not in isoinfo[1]:
        return None
    arch = None
    variant = None
    ver = None
    diskdefs = isoinfo[1]['README.diskdefines']
    for info in diskdefs.split(b'\n'):
        if not info:
            continue
        _, key, val = info.split(b' ', 2)
        val = val.strip()
        if key == b'ARCH':
            arch = val
            if arch == b'amd64':
                arch = b'x86_64'
        elif key == b'DISKNAME':
            variant, ver, _ = val.split(b' ', 2)
            if variant != b'Ubuntu-Server':
                return None
    if variant:
        if not isinstance(ver, str):
            ver = ver.decode('utf8')
        if not isinstance(arch, str):
            arch = arch.decode('utf8')
        major = '.'.join(ver.split('.', 2)[:2])
        return {'name': 'ubuntu-{0}-{1}'.format(ver, arch),
                'method': EXTRACT|COPY,
                'extractlist': ['casper/vmlinuz', 'casper/initrd',
                'EFI/BOOT/BOOTx64.EFI', 'EFI/BOOT/grubx64.efi'
                ],
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
    major = ver.split('.', 1)[0]
    return {'name': 'rhel-{0}-{1}'.format(ver, arch), 'method': EXTRACT, 'category': 'el{0}'.format(major)}


def scan_iso(filename):
    filesizes = {}
    filecontents = {}
    with libarchive.file_reader(filename) as reader:
        for ent in reader:
            if str(ent).endswith('TRANS.TBL'):
                continue
            eventlet.sleep(0)
            filesizes[str(ent)] = ent.size
            if str(ent) in READFILES:
                filecontents[str(ent)] = b''
                for block in ent.get_blocks():
                    filecontents[str(ent)] += bytes(block)
    return filesizes, filecontents


def fingerprint(filename):
    with open(filename, 'rb') as archive:
        header = archive.read(32768)
        archive.seek(32769)
        if archive.read(6) == b'CD001\x01':
            # ISO image
            isoinfo = scan_iso(filename)
            name = None
            for fun in globals():
                if fun.startswith('check_'):
                    name = globals()[fun](isoinfo)
                    if name:
                        return name, isoinfo[0]
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
                    return imginfo, None


def import_image(filename, callback, backend=False):
    identity = fingerprint(filename)
    if not identity:
        return -1
    identity, imginfo = identity
    targpath = identity['name']
    if identity.get('subname', None):
        targpath += '/' + identity['subname']
    targpath = '/var/lib/confluent/distributions/' + targpath
    os.makedirs(targpath, 0o755)
    filename = os.path.abspath(filename)
    os.chdir(targpath)
    if not backend:
        print('Importing OS to ' + targpath + ':')
    printit({'progress': 0.0})
    if EXTRACT & identity['method']:
        extract_file(filename, callback=callback, imginfo=imginfo, extractlist=identity.get('extractlist', None))
    if COPY & identity['method']:
        basename = identity.get('copyto', os.path.basename(filename))
        targpath = os.path.join(targpath, basename)
        shutil.copyfile(filename, targpath)
    printit({'progress': 1.0})
    sys.stdout.write('\n')

def printit(info):
    sys.stdout.write('     \r{:.2f}%'.format(100 * info['progress']))
    sys.stdout.flush()


def list_distros():
    return os.listdir('/var/lib/confluent/distributions')

def list_profiles():
    return os.listdir('/var/lib/confluent/public/os/')

def get_profile_label(profile):
    with open('/var/lib/confluent/public/os/{0}/profile.yaml') as metadata:
        prof = yaml.safe_load(metadata)
    return prof.get('label', profile)

importing = {}
class MediaImporter(object):

    def __init__(self, media):
        self.worker = None
        self.profiles = []
        identity = fingerprint(media)
        self.percent = 0.0
        identity, _ = identity
        self.phase = 'copying'
        if not identity:
            raise Exception('Unrecognized OS Media')
        if 'subname' in identity:
            importkey = '{0}-{1}'.format(identity['name'], identity['subname'])
        else:
            importkey = identity['name']
        if importkey in importing:
            raise Exception('Media import already in progress for this media')
        self.importkey = importkey
        importing[importkey] = self
        self.importkey = importkey
        self.osname = identity['name']
        self.oscategory = identity.get('category', None)
        targpath = identity['name']
        self.distpath = '/var/lib/confluent/distributions/' + targpath
        if identity.get('subname', None):
            targpath += '/' + identity['subname']
        self.targpath = '/var/lib/confluent/distributions/' + targpath
        if os.path.exists(self.targpath):
            raise Exception('{0} already exists'.format(self.targpath))
        self.filename = os.path.abspath(media)
        self.importer = eventlet.spawn(self.importmedia)

    def stop(self):
        if self.worker and self.worker.poll() is None:
            self.worker.kill()

    @property
    def progress(self):
        return {'phase': self.phase, 'progress': self.percent, 'profiles': self.profiles}

    def importmedia(self):
        os.environ['PYTHONPATH'] = ':'.join(sys.path)
        with open(os.devnull, 'w') as devnull:
            self.worker = subprocess.Popen(
                [sys.executable, __file__, self.filename, '-b'],
                stdin=devnull, stdout=subprocess.PIPE)
        wkr = self.worker
        currline = b''
        while wkr.poll() is None:
            currline += wkr.stdout.read(1)
            if b'\r' in currline:
                val = currline.split(b'%')[0].strip()
                if val:
                    self.percent = float(val)
                currline = b''
        a = wkr.stdout.read(1)
        while a:
            currline += a
            if b'\r' in currline:
                val = currline.split(b'%')[0].strip()
                if val:
                    self.percent = float(val)
            currline = b''
            a = wkr.stdout.read(1)
        bootupdates = []
        if self.oscategory:
            defprofile = '/opt/confluent/lib/osdeploy/{0}'.format(
                self.oscategory)
            osd, osversion, arch = self.osname.split('-')
            for prof in os.listdir('{0}/profiles'.format(defprofile)):
                srcname = '{0}/profiles/{1}'.format(defprofile, prof)
                profname = '{0}-{1}'.format(self.osname, prof)
                dirname = '/var/lib/confluent/public/os/{0}'.format(profname)
                if os.path.exists(dirname):
                    continue
                oumask = os.umask(0o22)
                shutil.copytree(srcname, dirname)
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
                for initrd in os.listdir('{0}/initramfs'.format(defprofile)):
                    fullpath = '{0}/initramfs/{1}'.format(defprofile, initrd)
                    os.symlink(fullpath, '{0}/boot/initramfs/{1}'.format(dirname, initrd))
                os.symlink(
                    '/var/lib/confluent/public/site/initramfs.cpio',
                    '{0}/boot/initramfs/site.cpio'.format(dirname))
                os.symlink(self.distpath, '{0}/distribution'.format(dirname))
                subprocess.check_call(
                    ['sh', '{0}/initprofile.sh'.format(dirname),
                    self.targpath, dirname])
                bootupdates.append(eventlet.spawn(update_boot, dirname))
                self.profiles.append(profname)
        for upd in bootupdates:
            upd.wait()
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
        sys.exit(import_image(sys.argv[1], callback=printit, backend=True))
    else:
        sys.exit(import_image(sys.argv[1], callback=printit))
