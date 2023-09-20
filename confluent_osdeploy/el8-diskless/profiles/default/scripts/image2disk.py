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

bootuuid = None

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
                yield md
        else:
            raise Exception('Installation from single part image not supported')

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
    with open(fstabfile) as tfile:
        fstab = tfile.read().split('\n')
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
                    if targetdev.startswith('/dev/localstorage/'):
                        entry[0] = targetdev
                    else:
                        uuid = subprocess.check_output(['blkid', '-s', 'UUID', '-o', 'value', targetdev]).decode('utf8')
                        uuid = uuid.strip()
                        entry[0] = 'UUID={}'.format(uuid)
                elif entry[2] == 'swap':
                    entry[0] = '/dev/mapper/localstorage-swap'
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
    shutil.rmtree(os.path.join(rootdir, 'etc/confluent/'))
    shutil.copytree('/etc/confluent', os.path.join(rootdir, 'etc/confluent'))
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
    with open(grubsyscfg) as defgrubin:
        defgrub = defgrubin.read().split('\n')
    with open(grubsyscfg, 'w') as defgrubout:
        for gline in defgrub:
            gline = gline.split()
            newline = []
            for ent in gline:
                if ent.startswith('resume=') or ent.startswith('rd.lvm.lv'):
                    continue
                newline.append(ent)
            defgrubout.write(' '.join(newline) + '\n')
    grubcfg = subprocess.check_output(['find', os.path.join(rootdir, 'boot'), '-name', 'grub.cfg']).decode('utf8').strip().replace(rootdir, '/').replace('//', '/')
    grubcfg = grubcfg.split('\n')
    if not grubcfg[-1]:
        grubcfg = grubcfg[:-1]
    if len(grubcfg) == 1:
        grubcfg = grubcfg[0]
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
        if 'nvme' in targblock and targblock[-1] == 'p':
            targblock = targblock[:-1]
        shimpath = subprocess.check_output(['find', os.path.join(rootdir, 'boot/efi'), '-name', 'shimx64.efi']).decode('utf8').strip()
        shimpath = shimpath.replace(rootdir, '/').replace('/boot/efi', '').replace('//', '/').replace('/', '\\')
        subprocess.check_call(['efibootmgr', '-c', '-d', targblock, '-l', shimpath, '--part', partnum])
    #other network interfaces


def had_swap():
    with open('/etc/fstab') as tabfile:
        tabs = tabfile.read().split('\n')
        for tab in tabs:
            tab = tab.split()
            if len(tab) < 3:
                continue
            if tab[2] == 'swap':
                return True
    return False

def install_to_disk(imgpath):
    global bootuuid
    lvmvols = {}
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
        deftotsize += fs['initsize']
        mintotsize += fs['minsize']
        if fs['initsize'] > biggestsize:
            biggestfs = fs
            biggestsize = fs['initsize']
        if fs['device'].startswith('/dev/mapper'):
            lvmvols[fs['device'].replace('/dev/mapper/', '')] = fs
            deflvmsize += fs['initsize']
            minlvmsize += fs['minsize']
        else:
            plainvols[int(re.search('(\d+)$', fs['device'])[0])] = fs
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
        curroffset += size + 1
    if not lvmvols:
        if swapsize:
            swapsize = swapsize // sectorsize
            swapsize += 2047 - (size % 2048)
            end = curroffset + swapsize
            if end > sectors:
                end = sectors
            parted.run('mkpart swap {}s {}s'.format(curroffset, end))
            subprocess.check_call(['mkswap', get_partname(instdisk, volidx + 1)])
    else:
        parted.run('mkpart lvm {}s 100%'.format(curroffset))
        lvmpart = get_partname(instdisk, volidx + 1)
        subprocess.check_call(['pvcreate', '-ff', '-y', lvmpart])
        subprocess.check_call(['vgcreate', 'localstorage', lvmpart])
        vginfo = subprocess.check_output(['vgdisplay', 'localstorage', '--units', 'b']).decode('utf8')
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
            vol = lvmvols[volidx]
            if vol is biggestfs:
                continue
            takeaway += vol['initsize'] // pesize
            takeaway += 1
        biggestextents = pes - takeaway
        for volidx in lvmvols:
            vol = lvmvols[volidx]
            if vol is biggestfs:
                extents = biggestextents
            else:
                extents = vol['initsize'] // pesize
                extents += 1
            if vol['mount'] == '/':
                lvname = 'root'
            else:
                lvname = vol['mount'].replace('/', '_')
            subprocess.check_call(['lvcreate', '-l', '{}'.format(extents), '-y', '-n', lvname, 'localstorage'])
            vol['targetdisk'] = '/dev/localstorage/{}'.format(lvname)
        if swapsize:
            subprocess.check_call(['lvcreate', '-y', '-l', '{}'.format(swapsize // pesize), '-n', 'swap', 'localstorage'])
            subprocess.check_call(['mkswap', '/dev/localstorage/swap'])
        os.makedirs('/run/imginst/targ')
        for vol in allvols:
            with open(vol['targetdisk'], 'wb') as partition:
                partition.write(b'\x00' * 1 * 1024 * 1024)
            subprocess.check_call(['mkfs.{}'.format(vol['filesystem']), vol['targetdisk']])
            subprocess.check_call(['mount', vol['targetdisk'], '/run/imginst/targ'])
            source = vol['mount'].replace('/', '_')
            source = '/run/imginst/sources/' + source
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
    install_to_disk(os.environ['mountsrc'])
