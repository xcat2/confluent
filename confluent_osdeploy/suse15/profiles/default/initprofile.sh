#!/bin/sh
ln -s $1/1/boot/x86_64/loader/linux $2/boot/kernel && \
ln -s $1/1/boot/x86_64/loader/initrd $2/boot/initramfs/distribution && \
mkdir -p $2/boot/media/EFI/BOOT && \
ln -s $1/1/EFI/BOOT/bootx64.efi $1/1/EFI/BOOT/grub.efi $2/boot/media/EFI/BOOT/
