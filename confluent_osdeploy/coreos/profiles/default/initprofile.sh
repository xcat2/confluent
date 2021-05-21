#!/bin/sh
ln -s $1/images/pxeboot/vmlinuz $2/boot/kernel && \
ln -s $1/images/pxeboot/initrd.img $2/boot/initramfs/distribution && \
ln -s $1/images/ignition.img $2/boot/initramfs/ignition.img && \
mkdir -p $2/boot/efi/boot/ && \
ln -s $1/images/pxeboot/rootfs.img $2/ && \
mcopy -i $1/images/efiboot.img ::efi/redhat/grubx64.efi $2/boot/efi/boot/ && \
mcopy -i $1/images/efiboot.img ::efi/boot/bootx64.efi $2/boot/efi/boot/