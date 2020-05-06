#!/bin/sh
ln -s $1/1/boot/x86_64/loader/linux $2/boot/kernel && \
ln -s $1/1/boot/x86_64/loader/initrd $2/boot/initramfs/distribution
