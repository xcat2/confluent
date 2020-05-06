#!/bin/sh
ln -s $1/images/pxeboot/vmlinuz $2/boot/kernel && \
ln -s $1/images/pxeboot/initrd.img $1/boot/initramfs/distribution
mkdir -p $2/boot/media/EFI/BOOT && \
ln -s $1/EFI/BOOT/BOOTX64.EFI $1/1/EFI/BOOT/grubx64.efi $2/boot/media/EFI/BOOT/

