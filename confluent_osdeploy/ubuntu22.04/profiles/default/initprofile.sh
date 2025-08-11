#!/bin/bash
set -e
sed -i 's/label: ubuntu/label: Ubuntu/' $2/profile.yaml
if [ -e $1/casper/hwe-vmlinuz ]; then
    ln -s $1/casper/hwe-vmlinuz $2/boot/kernel
else
    ln -s $1/casper/vmlinuz $2/boot/kernel
fi
if [ -e $1/casper/hwe-initrd ]; then
    ln -s $1/casper/hwe-initrd $2/boot/initramfs/distribution
else
    ln -s $1/casper/initrd $2/boot/initramfs/distribution
fi
mkdir -p $2/boot/efi/boot
if [ -d $1/EFI/boot/ ]; then
    ln -s $1/EFI/boot/* $2/boot/efi/boot
elif [ -d $1/efi/boot/ ]; then
    ln -s $1/efi/boot/* $2/boot/efi/boot
else
    echo "Unrecognized boot contents in media" >&2
    exit 1
fi

