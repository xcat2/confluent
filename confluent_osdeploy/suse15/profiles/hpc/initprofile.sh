#!/bin/sh
discnum=$(basename $1)
if [ "$discnum" != 1 ]; then exit 0; fi
if [ -e $2/boot/kernel ]; then exit 0; fi

if [[ $profile =~ ^sle.* ]]; then
    if ls $1/Product-* >& /dev/null; then
        ln -s $1 $2/product
    else
        ln -s ${1%1}2 $2/product
    fi
fi
sed -i 's/sle 15/SUSE Linux Enterprise 15/; s/opensuse_leap/openSUSE Leap/' $2/profile.yaml
ln -s $1/boot/x86_64/loader/linux $2/boot/kernel && \
ln -s $1/boot/x86_64/loader/initrd $2/boot/initramfs/distribution && \
mkdir -p $2/boot/efi/boot && \
ln -s $1/EFI/BOOT/bootx64.efi $1/EFI/BOOT/grub.efi $2/boot/efi/boot/
profile=$(basename $2)
if [[ $profile =~ ^sle.* ]]; then
	sed -i 's/%%IFSLE%%//;s/%%ENDIFSLE%%//' $2/autoyast
else
	sed -i '/%%IFSLE%%/,/%%ENDIFSLE%%/d' $2/autoyast
fi
