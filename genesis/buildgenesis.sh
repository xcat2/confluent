cd $(dirname $0)
cp -a 97genesis /usr/lib/dracut/modules.d/
cat /usr/lib/dracut/modules.d/97genesis/install-* > /usr/lib/dracut/modules.d/97genesis/install
chmod +x /usr/lib/dracut/modules.d/97genesis/install /usr/lib/dracut/modules.d/97genesis/installkernel
mkdir -p boot/initramfs
mkdir -p boot/efi/boot
dracut --no-early-microcode --xz -N -m "genesis base" -f boot/initramfs/distribution $(uname -r)
cp -f /boot/vmlinuz-$(uname -r) boot/kernel
cp /boot/efi/EFI/BOOT/BOOTX64.EFI boot/efi/boot
cp /boot/efi/EFI/centos/grubx64.efi boot/efi/boot/grubx64.efi
tar cf ~/rpmbuild/SOURCES/confluent-genesis.tar boot
rpmbuild -bb confluent-genesis.spec
rm -rf /usr/lib/dracut/modules.d/97genesis
cd -
# getting src rpms would be nice, but centos isn't consistent..
# /usr/lib/dracut/skipcpio /opt/confluent/genesis/x86_64/boot/initramfs/distribution | xzcat | cpio -dumiv
# rpm -qf $(find . -type f | sed -e 's/^.//') |sort -u|grep -v 'not owned' > ../rpmlist
# for f in $(find . -type f | sed -e 's/^.//'); do echo -n $f:; rpm -qf $f ; done > ../annotedrprmlist
# for i in $(cat rpmlist); do rpm -qi $i|grep Source; done |awk '{print $4}'|sort -u > srcrpmlist
# for i in $(cat ../srcrpmlist); do wget --continue http://vault.centos.org/8.2.2004/BaseOS/Source/SPackages/$i; done
# ls > downloadedsrcpmlist
# diff -u srcpmlist downloadedsrcrpmlist
# diff -u srcrpmlist downloadedsrcpmrlist |grep ^-|grep -v srcrpmlist
# for i in $(diff -u srcrpmlist downloadedsrcpmrlist |grep ^-|grep -v srcrpmlist|sed -e s/-//); do wget --continue http://vault.centos.org/8.2.2004/AppStream/Source/SPackages/$i; done



