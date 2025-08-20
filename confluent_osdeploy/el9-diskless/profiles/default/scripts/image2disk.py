#!/usr/bin/python3
import glob
import json
import os
import re
import time
import shutil
import socket
import stat
import struct
import sys
import subprocess
import traceback
try:
    import yaml
except ImportError:
    yaml = None

bootuuid = None
vgname = 'localstorage'
oldvgname = None

def convert_lv(oldlvname):
    if oldvgname is None:
        return None
    return oldlvname.replace(oldvgname, vgname)

def get_partname(devname, idx):
    if devname[-1] in '0123456789':
        return '{}p{}'.format(devname, idx)
    else:
        return '{}{}'.format(devname, idx)

def get_next_part_meta(img, imgsize):
    if img.tell() == imgsize:
        return None
    pathlen = struct.unpack('!H', img.read(2))[0]
    mountpoint = img.read(pathlen).decode('utf8')
    jsonlen = struct.unpack('!I', img.read(4))[0]
    metadata = json.loads(img.read(jsonlen).decode('utf8'))
    img.seek(16, 1) # skip the two 64-bit values we don't use, they are in json
    nextlen = struct.unpack('!H', img.read(2))[0]
    img.seek(nextlen, 1) # skip filesystem type
    nextlen = struct.unpack('!H', img.read(2))[0]
    img.seek(nextlen, 1) # skip orig devname (redundant with json)
    nextlen = struct.unpack('!H', img.read(2))[0]
    img.seek(nextlen, 1) # skip padding
    nextlen = struct.unpack('!Q', img.read(8))[0]
    img.seek(nextlen, 1)  # go to next section
    return metadata

def get_multipart_image_meta(img):
    img.seek(0, 2)
    imgsize = img.tell()
    img.seek(16)
    seekamt = img.read(1)
    img.seek(struct.unpack('B', seekamt)[0], 1)
    partinfo = get_next_part_meta(img, imgsize)
    while partinfo:
        yield partinfo
        partinfo = get_next_part_meta(img, imgsize)

def get_image_metadata(imgpath):
    with open(imgpath, 'rb') as img:
        header = img.read(16)
        if header == b'\x63\x7b\x9d\x26\xb7\xfd\x48\x30\x89\xf9\x11\xcf\x18\xfd\xff\xa1':
            for md in get_multipart_image_meta(img):
                if md.get('device', '').startswith('/dev/zram'):
                    continue
                yield md
        else:
            # plausible filesystem structure to apply to a nominally "diskless" image
            yield {'mount': '/', 'filesystem': 'xfs', 'minsize': 4294967296, 'initsize': 954128662528, 'flags': 'rw,seclabel,relatime,attr2,inode64,logbufs=8,logbsize=32k,noquota', 'device': '/dev/mapper/root', 'compressed_size': 27022069760}
            yield {'mount': '/boot', 'filesystem': 'xfs', 'minsize': 536870912, 'initsize': 1006632960, 'flags': 'rw,seclabel,relatime,attr2,inode64,logbufs=8,logbsize=32k,noquota', 'device': '/dev/nvme1n1p2', 'compressed_size': 171462656}
            yield {'mount': '/boot/efi', 'filesystem': 'vfat', 'minsize': 33554432, 'initsize': 627900416, 'flags': 'rw,relatime,fmask=0077,dmask=0077,codepage=437,iocharset=ascii,shortname=winnt,errors=remount-ro', 'device': '/dev/nvme1n1p1', 'compressed_size': 1576960}
            #raise Exception('Installation from single part image not supported')

class PartedRunner():
    def __init__(self, disk):
        self.disk = disk

    def run(self, command, check=True):
        command = command.split()
        command = ['parted', '-a', 'optimal', '-s', self.disk] + command
        if check:
            return subprocess.check_output(command).decode('utf8')
        else:
            return subprocess.run(command, stdout=subprocess.PIPE).stdout.decode('utf8')

def fixup(rootdir, vols):
    devbymount = {}
    for vol in vols:
        devbymount[vol['mount']] = vol['targetdisk']
    fstabfile = os.path.join(rootdir, 'etc/fstab')
    if os.path.exists(fstabfile):
        with open(fstabfile) as tfile:
            fstab = tfile.read().split('\n')
    else:
        #diskless image, need to invent fstab
        fstab = [
            "#ORIGFSTAB#/dev/mapper/root# /                       xfs     defaults        0 0",
            "#ORIGFSTAB#UUID=aaf9e0f9-aa4d-4d74-9e75-3537620cfe23# /boot                   xfs     defaults        0 0",
            "#ORIGFSTAB#UUID=C21D-B881#          /boot/efi               vfat    umask=0077,shortname=winnt 0 2",
            "#ORIGFSTAB#/dev/mapper/swap# none                    swap    defaults        0 0",
        ]
    while not fstab[0]:
        fstab = fstab[1:]
    if os.path.exists(os.path.join(rootdir, '.autorelabel')):
        os.unlink(os.path.join(rootdir, '.autorelabel'))
    with open(fstabfile, 'w') as tfile:
        for tab in fstab:
            entry = tab.split()
            if tab.startswith('#ORIGFSTAB#'):
                if entry[1] in devbymount:
                    targetdev = devbymount[entry[1]]
                    if targetdev.startswith('/dev/{}/'.format(vgname)):
                        entry[0] = targetdev
                    else:
                        uuid = subprocess.check_output(['blkid', '-s', 'UUID', '-o', 'value', targetdev]).decode('utf8')
                        uuid = uuid.strip()
                        entry[0] = 'UUID={}'.format(uuid)
                elif entry[2] == 'swap':
                    entry[0] = '/dev/mapper/{}-swap'.format(vgname.replace('-', '--'))
                entry[0] = entry[0].ljust(42)
                entry[1] = entry[1].ljust(16)
                entry[3] = entry[3].ljust(28)
                tab = '\t'.join(entry)
            tfile.write(tab + '\n')
    with open(os.path.join(rootdir, 'etc/hostname'), 'w') as nameout:
        nameout.write(socket.gethostname() + '\n')
    selinuxconfig = os.path.join(rootdir, 'etc/selinux/config')
    policy = None
    if os.path.exists(selinuxconfig):
        with open(selinuxconfig) as cfgin:
            sec = cfgin.read().split('\n')
            for l in sec:
                l = l.split('#', 1)[0]
                if l.startswith('SELINUXTYPE='):
                    _, policy = l.split('=')
    for sshkey in glob.glob(os.path.join(rootdir, 'etc/ssh/*_key*')):
        os.unlink(sshkey)
    for sshkey in glob.glob('/etc/ssh/*_key*'):
        newkey = os.path.join(rootdir, sshkey[1:])
        shutil.copy2(sshkey, newkey)
        finfo = os.stat(sshkey)
        os.chown(newkey, finfo[stat.ST_UID], finfo[stat.ST_GID])
    for ifcfg in glob.glob(os.path.join(rootdir, 'etc/sysconfig/network-scripts/*')):
        os.unlink(ifcfg)
    for ifcfg in glob.glob(os.path.join(rootdir, 'etc/NetworkManager/system-connections/*')):
        os.unlink(ifcfg)
    for ifcfg in glob.glob('/run/NetworkManager/system-connections/*'):
        newcfg = ifcfg.split('/')[-1]
        newcfg = os.path.join(rootdir, 'etc/NetworkManager/system-connections/{0}'.format(newcfg))
        shutil.copy2(ifcfg, newcfg)
    rootconfluentdir = os.path.join(rootdir, 'etc/confluent/')
    if os.path.exists(rootconfluentdir):
        shutil.rmtree(rootconfluentdir)
    shutil.copytree('/etc/confluent', rootconfluentdir)
    if policy:
        sys.stdout.write('Applying SELinux labeling...')
        sys.stdout.flush()
        subprocess.check_call(['setfiles', '-r', rootdir, os.path.join(rootdir, 'etc/selinux/{}/contexts/files/file_contexts'.format(policy)), os.path.join(rootdir, 'etc')])
        subprocess.check_call(['setfiles', '-r', rootdir, os.path.join(rootdir, 'etc/selinux/{}/contexts/files/file_contexts'.format(policy)), os.path.join(rootdir, 'opt')])
        sys.stdout.write('Done\n')
        sys.stdout.flush()
    for metafs in ('proc', 'sys', 'dev'):
        subprocess.check_call(['mount', '-o', 'bind', '/{}'.format(metafs), os.path.join(rootdir, metafs)])
    if os.path.exists(os.path.join(rootdir, 'etc/lvm/devices/system.devices')):
        os.remove(os.path.join(rootdir, 'etc/lvm/devices/system.devices'))
    grubsyscfg = os.path.join(rootdir, 'etc/sysconfig/grub')
    if not os.path.exists(grubsyscfg):
        grubsyscfg = os.path.join(rootdir, 'etc/default/grub')
    kcmdline = os.path.join(rootdir, 'etc/kernel/cmdline')
    if os.path.exists(kcmdline):
        with open(kcmdline) as kcmdlinein:
            kcmdlinecontent = kcmdlinein.read()
        newkcmdlineent = []
        for ent in kcmdlinecontent.split():
            if ent.startswith('resume='):
                newkcmdlineent.append('resume={}'.format(newswapdev))
            elif ent.startswith('root='):
                newkcmdlineent.append('root={}'.format(newrootdev))
            elif ent.startswith('rd.lvm.lv='):
                nent = convert_lv(ent)
                if nent:
                    newkcmdlineent.append(ent)
                else:
                    newkcmdlineent.append(ent)
            else:
                newkcmdlineent.append(ent)
        with open(kcmdline, 'w') as kcmdlineout:
            kcmdlineout.write(' '.join(newkcmdlineent) + '\n')
    for loadent in glob.glob(os.path.join(rootdir, 'boot/loader/entries/*.conf')):
        with open(loadent) as loadentin:
            currentry = loadentin.read().split('\n')
        with open(loadent, 'w') as loadentout:
            for cfgline in currentry:
                cfgparts = cfgline.split()
                if not cfgparts or cfgparts[0] != 'options':
                    loadentout.write(cfgline + '\n')
                    continue
                newcfgparts = [cfgparts[0]]
                for cfgpart in cfgparts[1:]:
                    if cfgpart.startswith('root='):
                        newcfgparts.append('root={}'.format(newrootdev))
                    elif cfgpart.startswith('resume='):
                        newcfgparts.append('resume={}'.format(newswapdev))
                    elif cfgpart.startswith('rd.lvm.lv='):
                        ncfgpart = convert_lv(cfgpart)
                        if ncfgpart:
                            newcfgparts.append(ncfgpart)
                        else:
                            newcfgparts.append(cfgpart)
                    else:
                        newcfgparts.append(cfgpart)
                loadentout.write(' '.join(newcfgparts) + '\n')
    if os.path.exists(grubsyscfg):
        with open(grubsyscfg) as defgrubin:
            defgrub = defgrubin.read().split('\n')
    else:
        defgrub = [
        'GRUB_TIMEOUT=5',
        'GRUB_DISTRIBUTOR="$(sed ' + "'s, release .*$,,g'" + ' /etc/system-release)"',
        'GRUB_DEFAULT=saved',
        'GRUB_DISABLE_SUBMENU=true',
        'GRUB_TERMINAL=""',
        'GRUB_SERIAL_COMMAND=""',
        'GRUB_CMDLINE_LINUX="crashkernel=1G-4G:192M,4G-64G:256M,64G-:512M rd.lvm.lv=vg/root rd.lvm.lv=vg/swap"',
        'GRUB_DISABLE_RECOVERY="true"',
        'GRUB_ENABLE_BLSCFG=true',
        ]
    if not os.path.exists(os.path.join(rootdir, "etc/kernel/cmdline")):
        with open(os.path.join(rootdir, "etc/kernel/cmdline"), "w") as cmdlineout:
            cmdlineout.write("root=/dev/mapper/localstorage-root rd.lvm.lv=localstorage/root")
    with open(grubsyscfg, 'w') as defgrubout:
        for gline in defgrub:
            gline = gline.split()
            newline = []
            for ent in gline:
                if ent.startswith('resume='):
                    newline.append('resume={}'.format(newswapdev))
                elif ent.startswith('root='):
                    newline.append('root={}'.format(newrootdev))
                elif ent.startswith('rd.lvm.lv='):
                    nent = convert_lv(ent)
                    if nent:
                        newline.append(nent)
                    else
                        newline.append(ent)
                else:
                    newline.append(ent)
            defgrubout.write(' '.join(newline) + '\n')
    grubcfg = subprocess.check_output(['find', os.path.join(rootdir, 'boot'), '-name', 'grub.cfg']).decode('utf8').strip().replace(rootdir, '/').replace('//', '/')
    grubcfg = grubcfg.split('\n')
    if not grubcfg[-1]:
        grubcfg = grubcfg[:-1]
    if len(grubcfg) == 1:
        grubcfg = grubcfg[0]
    elif not grubcfg:
        grubcfg = '/boot/grub2/grub.cfg'
        paths = glob.glob(os.path.join(rootdir, 'boot/efi/EFI/*'))
        for path in paths:
            with open(os.path.join(path, 'grub.cfg'), 'w') as stubgrubout:
                stubgrubout.write("search --no-floppy --root-dev-only --fs-uuid --set=dev " + bootuuid + "\nset prefix=($dev)/grub2\nexport $prefix\nconfigfile $prefix/grub.cfg\n")
    else:
        for gcfg in grubcfg:
            rgcfg = os.path.join(rootdir, gcfg[1:])  # gcfg has a leading / to get rid of
            if os.stat(rgcfg).st_size > 256:
                grubcfg = gcfg
            else:
                with open(rgcfg, 'r') as gin:
                    tgrubcfg = gin.read()
                tgrubcfg = tgrubcfg.split('\n')
                if 'search --no-floppy --fs-uuid --set=dev' in tgrubcfg[0]:
                    tgrubcfg[0] = 'search --no-floppy --fs-uuid --set=dev ' + bootuuid
                with open(rgcfg, 'w') as gout:
                    for gcline in tgrubcfg:
                        gout.write(gcline)
                        gout.write('\n')
    try:
        subprocess.check_call(['chroot', rootdir, 'grub2-mkconfig', '-o', grubcfg])
    except Exception as e:
        print(repr(e))
        print(rootdir)
        print(grubcfg)
        time.sleep(86400)
    newroot = None
    with open('/etc/shadow') as shadowin:
        shents = shadowin.read().split('\n')
        for shent in shents:
            shent = shent.split(':')
            if not shent:
                continue
            if shent[0] == 'root' and shent[1] not in ('*', '!!', ''):
                newroot = shent[1]
    if newroot:
        shlines = None
        with open(os.path.join(rootdir, 'etc/shadow')) as oshadow:
            shlines = oshadow.read().split('\n')
        with open(os.path.join(rootdir, 'etc/shadow'), 'w') as oshadow:
            for line in shlines:
                if line.startswith('root:'):
                    line = line.split(':')
                    line[1] = newroot
                    line = ':'.join(line)
                oshadow.write(line + '\n')
    partnum = None
    targblock = None
    for vol in vols:
        if vol['mount'] == '/boot/efi':
            targdev = vol['targetdisk']
            partnum = re.search('(\d+)$', targdev).group(1)
            targblock = re.search('(.*)\d+$', targdev).group(1)
    if targblock:
        if targblock.endswith('p') and 'nvme' in targblock:
            targblock = targblock[:-1]
        shimpath = subprocess.check_output(['find', os.path.join(rootdir, 'boot/efi'), '-name', 'shimx64.efi']).decode('utf8').strip()
        shimpath = shimpath.replace(rootdir, '/').replace('/boot/efi', '').replace('//', '/').replace('/', '\\')
        subprocess.check_call(['efibootmgr', '-c', '-d', targblock, '-l', shimpath, '--part', partnum])

    try:
        os.makedirs(os.path.join(rootdir, 'opt/confluent/bin'))
    except Exception:
        pass
    shutil.copy2('/opt/confluent/bin/apiclient', os.path.join(rootdir, 'opt/confluent/bin/apiclient'))
    #other network interfaces


def had_swap():
    if not os.path.exists('/etc/fstab'):
        # diskless source, assume swap
        return True
    with open('/etc/fstab') as tabfile:
        tabs = tabfile.read().split('\n')
        for tab in tabs:
            tab = tab.split()
            if len(tab) < 3:
                continue
            if tab[2] == 'swap':
                return True
    return False

newrootdev = None
newswapdev = None
vgmap = None
def install_to_disk(imgpath):
    global vgmap
    global bootuuid
    global newrootdev
    global newswapdev
    global vgname
    global oldvgname
    lvmvols = {}
    vgmap = {}
    deftotsize = 0
    mintotsize = 0
    deflvmsize = 0
    minlvmsize = 0
    biggestsize = 0
    biggestfs = None
    plainvols = {}
    allvols = []
    swapsize = 0
    if had_swap():
        with open('/proc/meminfo') as meminfo:
            swapsize = meminfo.read().split('\n')[0]
        swapsize = int(swapsize.split()[1])
        if swapsize < 2097152:
            swapsize = swapsize * 2
        elif swapsize > 8388608 and swapsize < 67108864:
            swapsize = swapsize * 0.5
        elif swapsize >= 67108864:
            swapsize = 33554432
        swapsize = int(swapsize * 1024)
    deftotsize = swapsize
    mintotsize = swapsize
    for fs in get_image_metadata(imgpath):
        allvols.append(fs)

        if fs['device'].startswith('/dev/mapper'):
            odevname = fs['device'].rsplit('/', 1)[-1]
            # if node has - then /dev/mapper will double up the hypen
            if '_' in odevname and '-' in odevname.split('_', 1)[-1]:
                oldvgname = odevname.rsplit('-', 1)[0].replace('--', '-')
                osname = oldvgname.split('_')[0]
                nodename = socket.gethostname().split('.')[0]
                vgname = '{}_{}'.format(osname, nodename)
            elif '-' in odevname: # unique one
                vgmap[odevname] = odevname.split('-')[0]
                lvmvols[odevname] = fs

                continue
            lvmvols[odevname] = fs
            deflvmsize += fs['initsize']
            minlvmsize += fs['minsize']
        else:
            plainvols[int(re.search('(\d+)$', fs['device'])[0])] = fs
        if fs['initsize'] > biggestsize:
            biggestfs = fs
            biggestsize = fs['initsize']
        deftotsize += fs['initsize']
        mintotsize += fs['minsize']
    with open('/tmp/installdisk') as diskin:
        instdisk = diskin.read()
    instdisk = '/dev/' + instdisk
    parted = PartedRunner(instdisk)
    dinfo = parted.run('unit s print', check=False)
    dinfo = dinfo.split('\n')
    sectors = 0
    sectorsize = 0
    for inf in dinfo:
        if inf.startswith('Disk {0}:'.format(instdisk)):
            _, sectors = inf.split(': ')
            sectors = int(sectors.replace('s', ''))
        if inf.startswith('Sector size (logical/physical):'):
            _, sectorsize = inf.split(':')
            sectorsize = sectorsize.split('/')[0]
            sectorsize = sectorsize.replace('B', '')
            sectorsize = int(sectorsize)
    # for now, only support resizing/growing the largest partition
    minexcsize = deftotsize - biggestfs['initsize']
    mintotsize = deftotsize - biggestfs['initsize'] + biggestfs['minsize']
    minsectors = mintotsize // sectorsize
    if sectors < (minsectors + 65536):
        raise Exception('Disk too small to fit image')
    biggestsectors = sectors - (minexcsize // sectorsize)
    biggestsize = sectorsize * biggestsectors
    parted.run('mklabel gpt')
    curroffset = 2048
    for volidx in sorted(plainvols):
        vol = plainvols[volidx]
        if vol is not biggestfs:
            size = vol['initsize'] // sectorsize
        else:
            size = biggestsize // sectorsize
        size += 2047 - (size % 2048)
        end = curroffset + size
        if end > sectors:
            end = sectors
        parted.run('mkpart primary {}s {}s'.format(curroffset, end))
        vol['targetdisk'] = get_partname(instdisk, volidx)
        if vol['mount'] == '/':
            newrootdev = vol['targetdisk']
        curroffset += size + 1
    if not lvmvols:
        if swapsize:
            swapsize = swapsize // sectorsize
            swapsize += 2047 - (size % 2048)
            end = curroffset + swapsize
            if end > sectors:
                end = sectors
            parted.run('mkpart swap {}s {}s'.format(curroffset, end))
            newswapdev = get_partname(instdisk, volidx + 1)
            subprocess.check_call(['mkswap', newswapdev])
    else:
        parted.run('mkpart lvm {}s 100%'.format(curroffset))
        lvmpart = get_partname(instdisk, volidx + 1)
        subprocess.check_call(['pvcreate', '-ff', '-y', lvmpart])
        subprocess.check_call(['vgcreate', vgname, lvmpart])
        vgroupmap = {}
        if yaml and vgmap:
            with open('/tmp/volumegroupmap.yml') as mapin:
                vgroupmap = yaml.safe_load(mapin)
        donedisks = {}
        for morevolname in vgmap:
            morevg = vgmap[morevolname]
            if morevg not in vgroupmap:
                raise Exception("No mapping defined to create volume group {}".format(morevg))
            targdisk = vgroupmap[morevg]
            if targdisk not in donedisks:
                moreparted = PartedRunner(targdisk)
                moreparted.run('mklabel gpt')
                moreparted.run('mkpart lvm 0% 100%')
                morelvmpart = get_partname(targdisk, 1)
                subprocess.check_call(['pvcreate', '-ff', '-y', morelvmpart])
                subprocess.check_call(['vgcreate', morevg, morelvmpart])
                donedisks[targdisk] = 1
            morelvname = morevolname.split('-', 1)[1]
            subprocess.check_call(['lvcreate', '-L', '{}b'.format(lvmvols[morevolname]['initsize']), '-y', '-n', morelvname, morevg])
            lvmvols[morevolname]['targetdisk'] = '/dev/{}/{}'.format(morevg, morelvname)

        vginfo = subprocess.check_output(['vgdisplay', vgname, '--units', 'b']).decode('utf8')
        vginfo = vginfo.split('\n')
        pesize = 0
        pes = 0
        for infline in vginfo:
            infline = infline.split()
            if len(infline) >= 3 and infline[:2] == ['PE', 'Size']:
                pesize = int(infline[2])
            if len(infline) >= 5 and infline[:2] == ['Free', 'PE']:
                pes = int(infline[4])
        takeaway = swapsize // pesize
        for volidx in lvmvols:
            if volidx in vgmap:
                # was handled previously
                continue
            vol = lvmvols[volidx]
            if vol is biggestfs:
                continue
            takeaway += vol['initsize'] // pesize
            takeaway += 1
        biggestextents = pes - takeaway
        for volidx in lvmvols:
            vol = lvmvols[volidx]
            if volidx in vgmap:
                # was handled previously
                continue

            if vol is biggestfs:
                extents = biggestextents
            else:
                extents = vol['initsize'] // pesize
                extents += 1
            if vol['mount'] == '/':
                lvname = 'root'

            else:
                lvname = vol['mount'].replace('/', '_')
            subprocess.check_call(['lvcreate', '-l', '{}'.format(extents), '-y', '-n', lvname, vgname])
            vol['targetdisk'] = '/dev/{}/{}'.format(vgname, lvname)
            if vol['mount'] == '/':
                newrootdev = vol['targetdisk']
        if swapsize:
            subprocess.check_call(['lvcreate', '-y', '-l', '{}'.format(swapsize // pesize), '-n', 'swap', vgname])
            subprocess.check_call(['mkswap', '/dev/{}/swap'.format(vgname)])
            newswapdev = '/dev/{}/swap'.format(vgname)
        os.makedirs('/run/imginst/targ')
        for vol in allvols:
            with open(vol['targetdisk'], 'wb') as partition:
                partition.write(b'\x00' * 1 * 1024 * 1024)
            subprocess.check_call(['mkfs.{}'.format(vol['filesystem']), vol['targetdisk']])
            subprocess.check_call(['mount', vol['targetdisk'], '/run/imginst/targ'])
            source = vol['mount'].replace('/', '_')
            source = '/run/imginst/sources/' + source
            if not os.path.exists(source):
                source = '/run/imginst/sources/_' + vol['mount']
            blankfsstat = os.statvfs('/run/imginst/targ')
            blankused = (blankfsstat.f_blocks - blankfsstat.f_bfree) * blankfsstat.f_bsize
            sys.stdout.write('\nWriting {0}: '.format(vol['mount']))
            with subprocess.Popen(['cp', '-ax', source + '/.', '/run/imginst/targ']) as copier:
                stillrunning = copier.poll()
                lastprogress = 0.0
                while stillrunning is None:
                    currfsstat = os.statvfs('/run/imginst/targ')
                    currused = (currfsstat.f_blocks - currfsstat.f_bfree) * currfsstat.f_bsize
                    currused -= blankused
                    with open('/proc/meminfo') as meminf:
                        for line in meminf.read().split('\n'):
                            if line.startswith('Dirty:'):
                                _, dirty, _ = line.split()
                                dirty = int(dirty) * 1024
                    progress = (currused - dirty) / vol['minsize']
                    if progress < lastprogress:
                        progress = lastprogress
                    if progress > 0.99:
                        progress = 0.99
                    lastprogress = progress
                    progress = progress * 100
                    sys.stdout.write('\x1b[1K\rWriting {0}: {1:3.2f}%'.format(vol['mount'], progress))
                    sys.stdout.flush()
                    time.sleep(0.5)
                    stillrunning = copier.poll()
                if stillrunning != 0:
                    raise Exception("Error copying volume")
                with subprocess.Popen(['sync']) as syncrun:
                    stillrunning = syncrun.poll()
                    while stillrunning is None:
                        with open('/proc/meminfo') as meminf:
                            for line in meminf.read().split('\n'):
                                if line.startswith('Dirty:'):
                                    _, dirty, _ = line.split()
                                    dirty = int(dirty) * 1024
                        progress = (vol['minsize'] - dirty) / vol['minsize']
                        if progress < lastprogress:
                            progress = lastprogress
                        if progress > 0.99:
                            progress = 0.99
                        lastprogress = progress
                        progress = progress * 100
                        sys.stdout.write('\x1b[1K\rWriting {0}: {1:3.2f}%'.format(vol['mount'], progress))
                        sys.stdout.flush()
                        time.sleep(0.5)
                        stillrunning = syncrun.poll()
                sys.stdout.write('\x1b[1K\rDone writing {0}'.format(vol['mount']))
                sys.stdout.write('\n')
                sys.stdout.flush()
                if vol['mount'] == '/boot':
                    tbootuuid = subprocess.check_output(['blkid', vol['targetdisk']])
                    if b'UUID="' in tbootuuid:
                        bootuuid = tbootuuid.split(b'UUID="', 1)[1].split(b'"')[0].decode('utf8')




            subprocess.check_call(['umount', '/run/imginst/targ'])
        for vol in allvols:
            subprocess.check_call(['mount', vol['targetdisk'], '/run/imginst/targ/' + vol['mount']])
        fixup('/run/imginst/targ', allvols)


if __name__ == '__main__':
    try:
        install_to_disk(os.environ['mountsrc'])
    except Exception:
        traceback.print_exc()
        time.sleep(86400)
        raise
