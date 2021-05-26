#!/usr/bin/python
import ctypes
import ctypes.util
import glob
import optparse
import os
import re
import shutil
import struct
import subprocess
import tempfile
try:
    import configparser
except ImportError:
    import ConfigParser as configparser
import dnf.rpm

libc = ctypes.CDLL(ctypes.util.find_library('c'))
CLONE_NEWNS = 0x00020000
CLONE_NEWCGROUP = 0x02000000
CLONE_NEWUTS = 0x04000000
CLONE_NEWIPC = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID = 0x20000000
PR_SET_NO_NEW_PRIVS = 38
PR_SET_DUMPABLE = 4
MS_RDONLY = 1
MS_REMOUNT = 32
MS_BIND = 4096
MS_REC = 16384
MS_PRIVATE = 1<<18


numregex = re.compile('([0-9]+)')

def naturalize_string(key):
    """Analyzes string in a human way to enable natural sort

    :param nodename: The node name to analyze
    :returns: A structure that can be consumed by 'sorted'
    """
    return [int(text) if text.isdigit() else text.lower()
            for text in re.split(numregex, key)]

def natural_sort(iterable):
    """Return a sort using natural sort if possible

    :param iterable:
    :return:
    """
    try:
        return sorted(iterable, key=naturalize_string)
    except TypeError:
        # The natural sort attempt failed, fallback to ascii sort
        return sorted(iterable)


def get_kern_version(filename):
    with open(filename, 'rb') as kernfile:
        kernfile.seek(0x20e)
        offset = struct.unpack('<H', kernfile.read(2))[0] + 0x200
        kernfile.seek(offset)
        verinfo = kernfile.read(128)
        version, _ = verinfo.split(b' ', 1)
        if not isinstance(version, str):
            version = version.decode('utf8')
        return version


def mkdirp(path):
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno != 17:
            raise


def run_constrained(function, args):
    # first fork to avoid changing namespace of unconstrained environment
    pid = os.fork()
    if pid:
        os.waitpid(pid, 0)
        return
    libc.unshare(CLONE_NEWNS|CLONE_NEWPID)
    # must fork again due to CLONE_NEWPID, or else lose the ability to make
    # subprocesses
    pid = os.fork()
    if pid:
        os.waitpid(pid, 0)
        os._exit(0)
        return
    # we are pid 1 now
    _mount('none', '/', flags=MS_REC|MS_PRIVATE)
    _mount('proc', '/proc', fstype='proc')
    function(args)
    os._exit(0)


def create_yumconf(sourcedir):
    repodir = tempfile.mkdtemp(prefix='genimage-yumrepos.d-')
    yumconf = open(os.path.join(repodir, 'repos.repo'), 'w+')
    if '/' not in sourcedir:
        sourcedir = os.path.join('/var/lib/confluent/distributions', sourcedir)
    if os.path.exists(sourcedir + '/repodata'):
        pass
    else:
        c = configparser.ConfigParser()
        c.read(sourcedir + '/.treeinfo')
        for sec in c.sections():
            if sec.startswith('variant-'):
                try:
                    repopath = c.get(sec, 'repository')
                except Exception:
                    continue
                _, varname = sec.split('-', 1)
                yumconf.write('[genimage-{0}]\n'.format(varname.lower()))
                yumconf.write('name=Local install repository for {0}\n'.format(varname))
                currdir = os.path.join(sourcedir, repopath)
                yumconf.write('baseurl={0}\n'.format(currdir))
                yumconf.write('enabled=1\ngpgcheck=0\n\n')
    return repodir


def main():
    parser = optparse.OptionParser()
    parser.add_option('-s', '--source', help='Directory to pull installation '
        'from (e.g. /var/lib/confluent/distributions/rocky-8.3-x86_64')
    parser.add_option(
        '-v', '--volume',
        help='Directory to make available in install environment.  -v / will '
        'cause it to be mounted in image as /run/external/, -v /:/run/root '
        'will override the target to be /run/root', action='append')
    (opts, args) = parser.parse_args()
    if args[0] == 'build':
        build_root(opts, args[1:])
    if args[0] == 'exec':
        exec_root(opts, args[1:])


def exec_root(opts, args):
    run_constrained(exec_root_backend, (opts, args))

def exec_root_backend(optargs):
    opts, args = optargs
    installroot = args[0]
    imgname = os.path.basename(installroot)
    _mount_constrained_fs(opts, installroot)
    os.chroot(installroot)
    os.chdir('/')
    os.environ['PS1'] = '[\x1b[1m\x1b[4mIMGUTIL EXEC {0}\x1b[0m \W]$ '.format(imgname)
    os.execv('/bin/bash', ['/bin/bash', '--login', '--noprofile'])


def _mount(src, dst, fstype=0, flags=0, options=0, mode=None):
    if not isinstance(src, bytes):
        src = src.encode('utf8')
    if fstype and not isinstance(fstype, bytes):
        fstype = fstype.encode('utf8')
    if not isinstance(dst, bytes):
        dst = dst.encode('utf8')
    res = libc.mount(src, dst, fstype, flags, options)
    if res:
        raise Exception('Unable to mount {0} on {1}'.format(src, dst))
    if mode is not None:
        os.chmod(dst, mode)

def build_root_backend(optargs):
    opts, args, yumargs = optargs
    installroot = args[0]
    _mount_constrained_fs(opts, installroot)
    subprocess.check_call(yumargs)
    mydir = os.path.dirname(__file__)
    dracutdir = os.path.join(mydir, 'dracut')
    targdir = os.path.join(installroot, 'usr/lib/dracut/modules.d/97diskless')
    shutil.copytree(dracutdir, targdir)
    cmd = ['chmod', 'a+x']
    cmd.extend(glob.glob(os.path.join(targdir, '*')))
    subprocess.check_call(cmd)
    kerns = glob.glob(os.path.join(installroot, 'boot/vmlinuz-*'))
    for kern in kerns:
        if '*' in kern:
            raise Exception("No kernels installed")
        if 'rescue' in kern:
            continue
        kver = get_kern_version(kern)
        print("Generating diskless initramfs for {0}".format(kver))
        subprocess.check_call(
            ['chroot', installroot, 'dracut', '--xz', '-N', '-m',
             'diskless base terminfo', '-f',
             '/boot/initramfs-diskless-{0}.img'.format(kver), kver])

def _mount_constrained_fs(opts, installroot):
    _mount('/dev', os.path.join(installroot, 'dev'), flags=MS_BIND|MS_RDONLY)
    _mount('proc', os.path.join(installroot, 'proc'), fstype='proc')
    _mount('sys', os.path.join(installroot, 'sys'), fstype='sysfs')
    _mount('runfs', os.path.join(installroot, 'run'), fstype='tmpfs')
    if opts.volume is None:
        opts.volume = []
    for v in opts.volume:
        if ':' in v:
            src, dst = v.split(':')
            dst = os.path.join(installroot, dst)
        else:
            src = v
            dst = os.path.join(installroot, 'run/external')
            dst = os.path.join(dst, v)
        mkdirp(dst)
        _mount(src, dst, flags=MS_BIND|MS_RDONLY)

def build_root(opts, args):
    yumargs = ['yum', '--installroot={0}'.format(args[0])]
    if opts.source:
        yumconfig = create_yumconf(opts.source)
        yumargs.extend(['--setopt=reposdir={0}'.format(yumconfig), '--disablerepo=*', '--enablerepo=genimage-*'])
    else:
        # default to using the host version, unless the target already has
        # it setup
        releasever = dnf.rpm.detect_releasever(args[0])
        if not releasever:
            releasever = dnf.rpm.detect_releasever('/')
        yumargs.extend(['--releasever={0}'.format(releasever)])
    yumargs.append('install')
    with open(os.path.join(os.path.dirname(__file__), 'pkglist'), 'r') as pkglist:
        pkgs = pkglist.read()
        pkgs = pkgs.split()
        yumargs.extend(pkgs)
    for dirname in ('proc', 'sys', 'dev', 'run'):
        mkdirp(os.path.join(args[0], dirname))
    run_constrained(build_root_backend, (opts, args, yumargs))
    if len(args) > 1:
        pack_image(opts, args)


def pack_image(opts, args):
    outdir = args[1]
    kerns = glob.glob(os.path.join(args[0], 'boot/vmlinuz-*'))
    kvermap = {}
    for kern in kerns:
        if 'rescue' in kern:
            continue
        kvermap[get_kern_version(kern)] = kern
    mostrecent = list(natural_sort(kvermap))[-1]
    initrdname = os.path.join(args[0], 'boot/initramfs-diskless-{0}.img'.format(mostrecent))
    mkdirp(os.path.join(outdir, 'boot/efi/boot'))
    mkdirp(os.path.join(outdir, 'boot/initramfs'))
    shutil.copyfile(kvermap[mostrecent], os.path.join(outdir, 'boot/kernel'))
    shutil.copyfile(initrdname, os.path.join(outdir, 'boot/initramfs/distribution'))
    shutil.copyfile(os.path.join(args[0], 'boot/efi/EFI/BOOT/BOOTX64.EFI'), os.path.join(outdir, 'boot/efi/boot/BOOTX64.EFI'))
    grubbin = None
    for candidate in glob.glob(os.path.join(args[0], 'boot/efi/EFI/*')):
        if 'BOOT' not in candidate:
            grubbin = os.path.join(candidate, 'grubx64.efi')
            break
    shutil.copyfile(grubbin, os.path.join(outdir, 'boot/efi/boot/grubx64.efi'))
    subprocess.check_call(['mksquashfs', args[0],
                           os.path.join(outdir, 'rootimg.sfs'), '-comp', 'xz'])




if __name__ == '__main__':
    main()
