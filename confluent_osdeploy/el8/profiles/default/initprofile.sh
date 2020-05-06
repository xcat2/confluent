#!/bin/sh
ln -s $1/images/pxeboot/vmlinuz $2/boot/kernel && \
ln -s $1/images/pxeboot/initrd.img $1/boot/initramfs/distribution

