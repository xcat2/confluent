#!/bin/sh
sed -i 's/centos/CentOS/; s/rhel/Red Hat Enterprise Linux/; s/oraclelinux/Oracle Linux/; s/alma/AlmaLinux/;s/fedora/Fedora Linux/' $2/profile.yaml
if grep Fedora $2/profile.yaml > /dev/null; then
	sed -i 's/@^minimal-environment/#/' $2/packagelist
fi
if grep ^label: $2/profile.yaml | grep 10 > /dev/null; then
	echo 'echo openssh-keysign >> /tmp/addonpackages' > $2/scripts/pre.d/enablekeysign
fi
ln -s $1/images/pxeboot/vmlinuz $2/boot/kernel && \
ln -s $1/images/pxeboot/initrd.img $2/boot/initramfs/distribution
mkdir -p $2/boot/efi/boot
if [ -e $1/EFI/BOOT/BOOTAA64.EFI ]; then
    ln -s $1/EFI/BOOT/BOOTAA64.EFI $1/EFI/BOOT/grubaa64.efi $2/boot/efi/boot/
else
    ln -s $1/EFI/BOOT/BOOTX64.EFI $1/EFI/BOOT/grubx64.efi $2/boot/efi/boot/
fi

