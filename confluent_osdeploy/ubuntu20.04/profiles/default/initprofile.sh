#!/bin/sh
ln -s $1/casper/vmlinuz $2/boot/kernel && \
ln -s $1/casper/initrd $2/boot/initramfs/distribution
