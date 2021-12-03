#!/bin/sh
profname=$(basename $2)
if file -L $1/images/ignition.img | grep gzip > /dev/null; then
    mkdir -p /var/lib/confluent/private/os/${profname}/pending/
    cd /var/lib/confluent/private/os/${profname}/pending/
    zcat $1/images/ignition.img | cpio -dumiv
fi
ln -s $1/images/pxeboot/vmlinuz $2/boot/kernel && \
ln -s $1/images/pxeboot/initrd.img $2/boot/initramfs/distribution && \
mkdir -p $2/boot/efi/boot/ && \
ln -s $1/images/pxeboot/rootfs.img $2/ && \
(mcopy -i $1/images/efiboot.img ::efi/redhat/grubx64.efi $2/boot/efi/boot/ || \
mcopy -i $1/images/efiboot.img ::efi/boot/grubx64.efi $2/boot/efi/boot/) && \
mcopy -i $1/images/efiboot.img ::efi/boot/bootx64.efi $2/boot/efi/boot/
