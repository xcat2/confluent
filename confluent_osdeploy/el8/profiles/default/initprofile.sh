#!/bin/sh
sed -i 's/centos/CentOS/; s/rhel/Red Hat Enterprise Linux/; s/oraclelinux/Oracle Linux/; s/alma/AlmaLinux/' $2/profile.yaml
ln -s $1/images/pxeboot/vmlinuz $2/boot/kernel && \
ln -s $1/images/pxeboot/initrd.img $2/boot/initramfs/distribution
mkdir -p $2/boot/efi/boot
if [ -e $1/EFI/BOOT/BOOTAA64.EFI ]; then
    ln -s $1/EFI/BOOT/BOOTAA64.EFI $1/EFI/BOOT/grubaa64.efi $2/boot/efi/boot/
else
    ln -s $1/EFI/BOOT/BOOTX64.EFI $1/EFI/BOOT/grubx64.efi $2/boot/efi/boot/
fi

