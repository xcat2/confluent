#!/bin/sh
sed -i 's/label: ubuntu/label: Ubuntu/' $2/profile.yaml && \
ln -s $1/casper/vmlinuz $2/boot/kernel && \
ln -s $1/casper/initrd $2/boot/initramfs/distribution && \
mkdir -p $2/boot/efi/boot && \
if [ -d $1/EFI/boot/ ]; then
    ln -s $1/EFI/boot/* $2/boot/efi/boot
elif [ -d $1/efi/boot/ ]; then
    ln -s $1/efi/boot/* $2/boot/efi/boot
else
    echo "Unrecogrized boot contents in media" >&2
    exit 1
fi

