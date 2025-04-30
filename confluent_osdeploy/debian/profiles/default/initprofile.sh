#!/bin/sh
sed -i 's/label: debian/label: Debian/' $2/profile.yaml && \
ln -s $1/linux $2/boot/kernel && \
ln -s $1/initrd.gz $2/boot/initramfs/distribution && \
mkdir -p $2/boot/efi/boot && \
mcopy -i $1/boot/grub/efi.img ::/efi/boot/* $2/boot/efi/boot

