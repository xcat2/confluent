#!/usr/bin/python

import os
import sys
import yaml

def mkdirp(path):
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno != 17:
            raise

def makeboot_tree(distribution, profiledir):
    bootdir = os.path.join(profiledir, 'boot')
    efisrc = os.path.join(distribution, 'EFI')
    efidir = os.path.join(bootdir, 'efi/boot')
    mkdirp(efidir)
    initrfsdir = os.path.join(bootdir, 'initramfs')
    mkdirp(initrfsdir)
    for directory in os.walk(efisrc):
        for filename in directory[2]:
            if filename.lower() == 'bootx64.efi':
                srcfile = os.path.join(directory[0], filename)
                trgfile = os.path.join(efidir, 'bootx64.efi')
                os.link(srcfile, trgfile)
            elif filename.lower() == 'grubx64.efi':
                srcfile = os.path.join(directory[0], filename)
                trgfile = os.path.join(efidir, 'grubx64.efi')
                os.link(srcfile, trgfile)
    netbootdir = os.path.join(distribution, 'images/pxeboot')
    srckern = os.path.join(netbootdir, 'vmlinuz')
    srcinitramfs = os.path.join(netbootdir, 'initrd.img')
    trgkern = os.path.join(bootdir, 'kernel')
    trginitramfs = os.path.join(initrfsdir, 'initrd.img')
    os.link(srckern, trgkern)
    os.link(srcinitramfs, trginitramfs)
    trginitramfs = os.path.join(initrfsdir, 'site-initramfs.gz')
    os.link('/var/lib/confluent/public/site/site-initramfs.gz', trginitramfs)
    profileinfo = os.path.join(profiledir, 'profile.yaml')
    with open(profileinfo) as info:
        profile = yaml.safe_load(info)
    cfgfile = os.path.join(efidir, 'grub.cfg')
    with open(cfgfile, 'w') as grubcfg:
        grubcfg.write('set timeout=5\n')
        grubcfg.write("menuentry '{0}' {{\n".format(
            profile.get('label', 'Unknown')))
        grubcfg.write('    linuxefi /kernel {0}\n'.format(profile.get(
                     'kernelargs', 'quiet')))
        initrds = ' '.join(
            ['/initramfs/{0}'.format(x) for x in os.listdir(initrfsdir)])
        grubcfg.write('    initrdefi {0}\n}}'.format(initrds))
    #TODO: create the netboot grub.cfg, is there a way to use grub http
    # without putting the server in the cfg?
    # If server is omitted, value of environment variable ‘net_default_server’
    # is used


if __name__ == '__main__':
    makeboot_tree(sys.argv[1], sys.argv[2])
