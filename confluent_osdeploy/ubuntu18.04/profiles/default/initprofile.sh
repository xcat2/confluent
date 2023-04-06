#!/bin/sh
sed -i 's/label: ubuntu/label: Ubuntu/' $2/profile.yaml && \
ln -s $1/install/hwe-netboot/ubuntu-installer/amd64/linux $2/boot/kernel && \
ln -s $1/install/hwe-netboot/ubuntu-installer/amd64/initrd.gz $2/boot/initramfs/distribution && \
mkdir -p $2/boot/efi/boot && \
ln -s $1/EFI/BOOT/* $2/boot/efi/boot

