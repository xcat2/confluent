#!/bin/sh
sed -i 's/label: ubuntu/label: Ubuntu/' $2/profile.yaml && \
ln -s $1/casper/vmlinuz $2/boot/kernel && \
ln -s $1/casper/initrd $2/boot/initramfs/distribution && \
mkdir -p $2/boot/efi/boot && \
ln -s $1/EFI/boot/* $2/boot/efi/boot

