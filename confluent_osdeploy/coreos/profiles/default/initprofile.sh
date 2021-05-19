#!/bin/sh
ln -s $1/images/pxeboot/vmlinuz $2/boot/kernel && \
ln -s $1/images/pxeboot/initrd.img $2/boot/initramfs/distribution && \
mkdir -p $2/boot/efi/boot/ && \
ln -s $1/images/pxeboot/rootfs.img $2/
