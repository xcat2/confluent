cd $(dirname $0)
cp -a 97genesis /usr/lib/dracut/modules.d/
cat /usr/lib/dracut/modules.d/97genesis/install-* > /usr/lib/dracut/modules.d/97genesis/install
chmod +x /usr/lib/dracut/modules.d/97genesis/install /usr/lib/dracut/modules.d/97genesis/installkernel
mkdir -p boot/initramfs
mkdir -p boot/efi/boot
dracut --xz -N -m "genesis base" -f boot/initramfs/distribution $(uname -r)
cp -f /boot/vmlinuz-$(uname -r) boot/kernel
cp /boot/efi/EFI/BOOT/BOOTX64.EFI boot/efi/boot
cp /boot/efi/EFI/centos/grubx64.efi boot/efi/boot/grubx64.efi
tar cf ~/rpmbuild/SOURCES/confluent-genesis.tar boot
rpmbuild -bb confluent-genesis.spec
rm -rf /usr/lib/dracut/modules.d/97genesis
cd -
# getting src rpms would be nice, but centos isn't consistent..
# skipcpio | xzcat | cpio -dumiv
# dnf download --source $(rpm -qf $(find . -type f | sed -e 's/^.//') |sort -u|grep -v 'not owned')

